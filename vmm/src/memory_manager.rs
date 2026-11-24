// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::cmp::Reverse;
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use std::collections::BTreeMap;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::mem::{self, MaybeUninit, zeroed};
use std::num::NonZeroUsize;
use std::ops::{BitAnd, Not, Sub};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Barrier, Mutex};
use std::{cmp, ffi, panic, process, result, thread, time};

use acpi_tables::{Aml, aml};
use anyhow::{Context, anyhow};
use arch::{RegionType, layout};
#[cfg(target_arch = "x86_64")]
use devices::ioapic;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracer::trace_scoped;
use virtio_devices::BlocksState;
use virtio_devices::mem::Error as VirtioMemError;
use virtio_devices::vhost_user::{PostcopyHandler, PostcopyRegion};
#[cfg(target_arch = "x86_64")]
use vm_allocator::GsiApic;
use vm_allocator::page_size::get_page_size;
use vm_allocator::{AddressAllocator, GuestRegionError, MemorySlotAllocator, SystemAllocator};
use vm_device::BusDevice;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::guest_memory::FileOffset;
use vm_memory::mmap::MmapRegionError;
use vm_memory::{
    Address, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryBackend,
    GuestMemoryError, GuestMemoryRegion, GuestUsize, MmapRegion,
};
use vm_migration::protocol::{MemoryRange, MemoryRangeTable};
use vm_migration::{
    Migratable, MigratableError, Pausable, Snapshot, SnapshotData, Snapshottable, Transportable,
    UffdError,
};
use vmm_sys_util::eventfd::EventFd;

use crate::config::MemoryRestoreMode;
#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::coredump::{
    CoredumpMemoryRegion, CoredumpMemoryRegions, DumpState, GuestDebuggableError,
};
use crate::migration::transport::SocketStream;
use crate::migration::url_to_path;
use crate::pagemap::PageMap;
use crate::sparse::{
    clone_file_range, copy_region, copy_region_dense, next_data_extent, write_region_sparse,
};
use crate::uffd::{
    self, FileUffdMemorySource, SocketUffdMemorySource, Uffd, UffdHole, UffdMemorySource, UffdRange,
};
use crate::vm_config::{HotplugMethod, MemoryConfig, MemoryZoneConfig};
use crate::{GuestMemory, GuestRegion, MEMORY_MANAGER_SNAPSHOT_ID, prefault, userfaultfd};

struct UffdHandler {
    stop_event: EventFd,
    result_rx: Receiver<Result<(), io::Error>>,
    handle: thread::JoinHandle<()>,
    fault_socket_fd: Option<OwnedFd>,
    uffd_registry: Arc<UffdRegistry>,
    copy_on_access: Option<CopyOnAccessPages>,
}

/// Userfaultfds sent to a UFFD handler.
pub(crate) struct UffdRegistry {
    added_uffds: Mutex<Vec<(String /* device identifier */, Uffd)>>,
    added_uffd_evt: EventFd,
    done: EventFd,
    ranges: Box<[UffdRange]>,
}

impl UffdRegistry {
    fn drain_added_uffds(&self) -> Vec<(String, Uffd)> {
        mem::take(&mut *self.added_uffds.lock().unwrap())
    }

    fn is_done(&self) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.done.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pollfd` is valid for the one descriptor polled.
        unsafe { libc::poll(&mut pollfd, 1, 0) == 1 }
    }
}

impl PostcopyHandler for UffdRegistry {
    // vhost-user backends get their memory regions through SET_MEM_TABLE and/or
    // ADD_MEM_REG requests. These requests send to the backends memory regions,
    // not the memory ranges. These two differs: we can have multiple memory
    // ranges in a single memory region. In practice, this doesn't really happen
    // and one region = one range (with the exception of virio-mem). However,
    // there is nothing that enforces this and we need this assumption to hold,
    // as we keep track of the served pages per uffd ranges. So, we take a
    // defensive approach and design against this by creating a copy of the
    // memory ranges for each backends (with an updated host_addr that reflects
    // the backend VMA).
    //
    // Ideally, we would unregister any memory that's not within a range, as to
    // have the kernel handle these pages. These pages should be 0s (eg. the
    // guest plugged a virtio-mem block). However, we can't unregister them
    // directly, as we have no guarantees that the vhost-user backends actually
    // have registered the region with userfaultfd. So, instead, keep track of
    // the holes, and when a fault happen on them, we can then unregister them.
    fn register_uffd_regions(
        &self,
        id: &str,
        fd: OwnedFd,
        regions: &[PostcopyRegion],
    ) -> Result<(), io::Error> {
        let mut added_uffds = self.added_uffds.lock().unwrap();
        if self.is_done() {
            return Ok(());
        }

        let mut ranges = Vec::new();
        for range in self.ranges.iter() {
            let Some(region) = regions.iter().find(|region| {
                range.host_addr >= region.host_addr
                    && range.host_addr + range.length <= region.host_addr + region.memory_size
            }) else {
                return Err(io::Error::other(format!(
                    "no region maps host range {:#x}-{:#x}",
                    range.host_addr,
                    range.host_addr + range.length
                )));
            };
            ranges.push(UffdRange {
                // Faults on `fd` are at the addresses where its process maps
                // guest memory, so translate the handler ranges to those
                host_addr: region.backend_addr + (range.host_addr - region.host_addr),
                ..*range
            });
        }

        let mut holes = Vec::new();
        for region in regions {
            let end = region.backend_addr + region.memory_size;
            let mut start = region.backend_addr;
            for range in &ranges {
                let in_region = range.host_addr >= region.backend_addr && range.host_addr < end;
                if !in_region {
                    continue;
                }
                if range.host_addr > start {
                    holes.push(UffdHole {
                        host_addr: start,
                        length: range.host_addr - start,
                    });
                }
                start = range.host_addr + range.length;
            }
            if start < end {
                holes.push(UffdHole {
                    host_addr: start,
                    length: end - start,
                });
            }
        }

        let entry = (id.to_string(), Uffd::new(fd, ranges.into(), holes.into())?);
        added_uffds.push(entry);
        self.added_uffd_evt.write(1)
    }

    fn postcopy_done_event(&self) -> &EventFd {
        &self.done
    }
}

/// How a UFFD handler serves guest memory.
enum UffdServing {
    /// Serve faults and, with `background_fetch_pages`, copy every page the
    /// guest has not accessed yet in the background, exiting once all are in.
    OnDemand { background_fetch_pages: bool },
    /// Serve faults for the VM's whole lifetime and never copy a page the
    /// guest has not accessed. A page the guest discarded after accessing it
    /// (balloon, free page reporting, virtio-mem unplug) comes back as zeroes,
    /// as after an eager copy. `source` is the restore source, kept for the
    /// snapshot writer.
    CopyOnAccess { source: File },
}

/// What a copy-on-access VM's snapshot writer needs: the pages the guest
/// never accessed are only in the snapshot the VM was restored from.
struct CopyOnAccessPages {
    source: File,
    ranges: Box<[UffdRange]>,
    served: Arc<[AtomicBitmap]>,
    /// Held by the handler from deciding how to resolve a fault until the
    /// page is installed and `served` updated. Holding it, `served` and the
    /// pages in memory agree.
    serve_lock: Arc<Mutex<()>>,
}

/// A part of a saved memory range and where its content is.
#[derive(Debug, PartialEq, Eq)]
enum CopyOnAccessSegment {
    /// In guest memory: outside every UFFD range, served, or present.
    Guest { offset: u64, len: u64 },
    /// Never served and not present: still only in the restore source, at
    /// `source_offset`.
    Source {
        offset: u64,
        len: u64,
        source_offset: u64,
    },
}

impl CopyOnAccessSegment {
    fn end(&self) -> u64 {
        match *self {
            Self::Guest { offset, len } | Self::Source { offset, len, .. } => offset + len,
        }
    }

    /// Extend `self` with `next` if it continues it. Returns whether it did.
    fn merge(&mut self, next: &Self) -> bool {
        match (self, next) {
            (
                Self::Guest { offset, len },
                Self::Guest {
                    offset: next,
                    len: next_len,
                },
            ) if *offset + *len == *next => *len += next_len,
            (
                Self::Source {
                    offset,
                    len,
                    source_offset,
                },
                Self::Source {
                    offset: next,
                    len: next_len,
                    source_offset: next_source,
                },
            ) if *offset + *len == *next && *source_offset + *len == *next_source => {
                *len += next_len;
            }
            _ => return false,
        }
        true
    }
}

impl CopyOnAccessPages {
    /// The longest leading part of the `len` bytes of guest memory mapped at
    /// `host_addr` whose content is all in one place, at offsets relative to
    /// `host_addr`. `page_present` tells whether the page at an address is in
    /// memory; it is asked only about pages never served. Call with
    /// `serve_lock` held, and the answer holds only as long as it is.
    fn next_segment(
        &self,
        host_addr: u64,
        len: u64,
        page_present: &impl Fn(u64) -> bool,
    ) -> CopyOnAccessSegment {
        let end = host_addr + len;
        let mut segment = self.piece(host_addr, host_addr, end, page_present);
        while host_addr + segment.end() < end {
            let next = self.piece(host_addr, host_addr + segment.end(), end, page_present);
            if !segment.merge(&next) {
                break;
            }
        }
        segment
    }

    /// The part of `[addr, end)` up to the end of the page at `addr`, or up
    /// to the next UFFD range when `addr` is in none, at an offset relative
    /// to `base`.
    fn piece(
        &self,
        base: u64,
        addr: u64,
        end: u64,
        page_present: &impl Fn(u64) -> bool,
    ) -> CopyOnAccessSegment {
        let Some((range_idx, range)) = self
            .ranges
            .iter()
            .enumerate()
            .find(|(_, r)| addr >= r.host_addr && addr < r.host_addr + r.length)
        else {
            let next = self
                .ranges
                .iter()
                .map(|r| r.host_addr)
                .filter(|&start| start > addr && start < end)
                .min()
                .unwrap_or(end);
            return CopyOnAccessSegment::Guest {
                offset: addr - base,
                len: next - addr,
            };
        };

        let page_idx = (addr - range.host_addr) / range.page_size;
        let page_end = (range.page_addr(page_idx) + range.page_size)
            .min(range.host_addr + range.length)
            .min(end);
        let offset = addr - base;
        let len = page_end - addr;
        if self.served[range_idx].is_bit_set(page_idx as usize)
            || page_present(range.page_addr(page_idx))
        {
            CopyOnAccessSegment::Guest { offset, len }
        } else {
            CopyOnAccessSegment::Source {
                offset,
                len,
                source_offset: range.source_offset + (addr - range.host_addr),
            }
        }
    }
}

pub const MEMORY_MANAGER_ACPI_SIZE: usize = 0x18;

const DEFAULT_MEMORY_ZONE: &str = "mem0";

/// No vhost-user device can have it: users can't pick ids starting with "__".
const VMM_UFFD_ID: &str = "__vmm";

/// Filename used to store guest RAM in snapshot directories.
pub const SNAPSHOT_FILENAME: &str = "memory-ranges";

#[cfg(target_arch = "x86_64")]
const X86_64_IRQ_BASE: u32 = 5;

const HOTPLUG_COUNT: usize = 8;
const HOTPLUG_RAM_ALIGN_SIZE: u64 = 128 << 20;
// Gap needed to ensure regions are not contiguous in guest physical address space
const HOTPLUG_RAM_GAP_SIZE: u64 = 256 << 20;

// Memory policy constants
const MPOL_BIND: u32 = 2;
const MPOL_MF_STRICT: u32 = 1;
const MPOL_MF_MOVE: u32 = 1 << 1;

// Reserve 1 MiB for platform MMIO devices (e.g. ACPI control devices)
const PLATFORM_DEVICE_AREA_SIZE: u64 = 1 << 20;

#[derive(Clone, Default, Serialize, Deserialize)]
struct HotPlugState {
    base: u64,
    length: u64,
    active: bool,
    inserting: bool,
    removing: bool,
}

pub struct VirtioMemZone {
    region: Arc<GuestRegion>,
    virtio_device: Option<Arc<Mutex<virtio_devices::Mem>>>,
    hotplugged_size: u64,
    hugepages: bool,
    blocks_state: Arc<Mutex<BlocksState>>,
}

impl VirtioMemZone {
    pub fn region(&self) -> &Arc<GuestRegion> {
        &self.region
    }
    pub fn set_virtio_device(&mut self, virtio_device: Arc<Mutex<virtio_devices::Mem>>) {
        self.virtio_device = Some(virtio_device);
    }
    pub fn hotplugged_size(&self) -> u64 {
        self.hotplugged_size
    }
    pub fn hugepages(&self) -> bool {
        self.hugepages
    }
    pub fn blocks_state(&self) -> &Arc<Mutex<BlocksState>> {
        &self.blocks_state
    }
    pub fn plugged_ranges(&self) -> MemoryRangeTable {
        self.blocks_state
            .lock()
            .unwrap()
            .memory_ranges(self.region.start_addr().raw_value(), true)
    }
}

pub struct MemoryZone {
    regions: Vec<Arc<GuestRegion>>,
    virtio_mem_zone: Option<VirtioMemZone>,
    shared: bool,
    hugepages: bool,
    backing_page_size: u64,
    mergeable: bool,
}

impl MemoryZone {
    fn new(shared: bool, hugepages: bool, backing_page_size: u64, mergeable: bool) -> Self {
        Self {
            regions: Vec::new(),
            virtio_mem_zone: None,
            shared,
            hugepages,
            backing_page_size,
            mergeable,
        }
    }

    pub fn regions(&self) -> &Vec<Arc<GuestRegion>> {
        &self.regions
    }
    pub fn virtio_mem_zone(&self) -> &Option<VirtioMemZone> {
        &self.virtio_mem_zone
    }
    pub fn virtio_mem_zone_mut(&mut self) -> Option<&mut VirtioMemZone> {
        self.virtio_mem_zone.as_mut()
    }

    fn backing_page_size_for_gpa(&self, gpa: u64) -> Option<u64> {
        if self.regions.iter().any(|region| {
            let start = region.start_addr().raw_value();
            gpa >= start && gpa < start + region.len()
        }) {
            return Some(self.backing_page_size);
        }

        self.virtio_mem_zone.as_ref().and_then(|virtio_mem_zone| {
            let start = virtio_mem_zone.region.start_addr().raw_value();
            (gpa >= start && gpa < start + virtio_mem_zone.region.len())
                .then_some(self.backing_page_size)
        })
    }
}

pub type MemoryZones = HashMap<String, MemoryZone>;

#[derive(Clone, Serialize, Deserialize)]
struct GuestRamMapping {
    slot: u32,
    gpa: u64,
    size: u64,
    zone_id: String,
    virtio_mem: bool,
    file_offset: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct ArchMemRegion {
    base: u64,
    size: usize,
    r_type: RegionType,
}

// Reserved ranges as (base, end), ascending.
fn reserved_spans(regions: &[ArchMemRegion]) -> Vec<(u64, u64)> {
    let mut spans: Vec<(u64, u64)> = regions
        .iter()
        .filter(|r| r.r_type == RegionType::Reserved)
        .map(|r| (r.base, r.base + r.size as u64))
        .collect();
    spans.sort_unstable();
    spans
}

// Moves base above any reserved range that a span of size would cross.
fn base_clear_of_reserved(regions: &[ArchMemRegion], base: u64, size: u64) -> u64 {
    let mut base = base;
    for (r_base, r_end) in reserved_spans(regions) {
        if base < r_end && r_base < base + size {
            base = r_end;
        }
    }
    base
}

// A hotplugged RAM region that would overlap a reserved range is placed after it,
// so the window must extend size bytes past any reserved range it crosses.
fn size_clear_of_reserved(regions: &[ArchMemRegion], base: u64, size: u64) -> Result<u64, Error> {
    let mut end = base.checked_add(size).ok_or(Error::GuestAddressOverFlow)?;
    for (r_base, r_end) in reserved_spans(regions) {
        if base < r_end && r_base < end {
            end = r_end.checked_add(size).ok_or(Error::GuestAddressOverFlow)?;
        }
    }
    Ok(end - base)
}

// The snapshot memory file a copy-on-write restore mapped guest RAM from.
struct CowSource {
    file: File,
    ranges: MemoryRangeTable,
    pagemap: PageMap,
}

pub struct MemoryManager {
    boot_guest_memory: GuestMemory,
    guest_memory: GuestMemoryAtomic<GuestMemory>,
    next_memory_slot: Arc<AtomicU32>,
    memory_slot_allocator: Arc<MemorySlotAllocator>,
    start_of_device_area: GuestAddress,
    end_of_device_area: GuestAddress,
    end_of_ram_area: GuestAddress,
    pub vm: Arc<dyn hypervisor::Vm>,
    hotplug_slots: Vec<HotPlugState>,
    selected_slot: usize,
    mergeable: bool,
    allocator: Arc<Mutex<SystemAllocator>>,
    hotplug_method: HotplugMethod,
    boot_ram: u64,
    current_ram: u64,
    hotplug_size: u64,
    next_hotplug_slot: usize,
    shared: bool,
    hugepages: bool,
    hugepage_size: Option<u64>,
    prefault: bool,
    reserve: Option<bool>,
    thp: bool,
    user_provided_zones: bool,
    snapshot_memory_ranges: MemoryRangeTable,
    cow_source: Option<CowSource>,
    memory_zones: MemoryZones,
    log_dirty: bool, // Enable dirty logging for created RAM regions
    arch_mem_regions: Vec<ArchMemRegion>,
    ram_allocator: AddressAllocator,
    dynamic: bool,

    // Keep slot and range metadata for guest RAM snapshots.
    // This is useful for getting the dirty pages as we need to know the
    // slots that the mapping is created in.
    guest_ram_mappings: Vec<GuestRamMapping>,
    uffd_handler: Option<UffdHandler>,

    pub acpi_address: Option<GuestAddress>,
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    uefi_flash: Option<GuestMemoryAtomic<GuestMemory>>,
}

#[derive(Error, Debug)]
pub enum Error {
    /// Failed to create shared file.
    #[error("Failed to create shared file")]
    SharedFileCreate(#[source] io::Error),

    /// Failed to set shared file length.
    #[error("Failed to set shared file length")]
    SharedFileSetLen(#[source] io::Error),

    /// Failed to seal shared file.
    #[error("Failed to seal shared file")]
    SharedFileSeal(#[source] io::Error),

    /// Guest region collection error
    #[error("Guest region collection error")]
    GuestRegionCollection(#[source] vm_memory::GuestRegionCollectionError),

    /// Failed to allocate a memory range.
    #[error("Failed to allocate a memory range")]
    MemoryRangeAllocation,

    /// Error from region creation
    #[error("Error from region creation")]
    GuestMemoryRegion(#[source] MmapRegionError),

    /// No ACPI slot available
    #[error("No ACPI slot available")]
    NoSlotAvailable,

    /// Not enough space in the hotplug RAM region
    #[error("Not enough space in the hotplug RAM region: {0} exceeds {1}")]
    InsufficientHotplugRam(u64, u64),

    /// The requested hotplug memory addition is not a valid size
    #[error("The requested hotplug memory addition is not a valid size")]
    InvalidSize,

    /// Failed to register a guest region.
    #[error("Failed to register a guest region")]
    RegisterGuestRegion(#[source] GuestRegionError),

    /// Failed to EventFd.
    #[error("Failed to EventFd")]
    EventFdFail(#[source] io::Error),

    /// Failed to virtio-mem resize
    #[error("Failed to virtio-mem resize")]
    VirtioMemResizeFail(#[source] VirtioMemError),

    /// Cannot restore VM
    #[error("Cannot restore VM")]
    Restore(#[source] MigratableError),

    /// Cannot restore VM because source URL is missing
    #[error("Cannot restore VM because source URL is missing")]
    RestoreMissingSourceUrl,

    /// Cannot create the system allocator
    #[error("Cannot create the system allocator")]
    CreateSystemAllocator,

    /// Failed creating a new MmapRegion instance.
    #[cfg(target_arch = "x86_64")]
    #[error("Failed creating a new MmapRegion instance")]
    NewMmapRegion(#[source] MmapRegionError),

    /// No memory zones found.
    #[error("No memory zones found")]
    MissingMemoryZones,

    /// Memory configuration is not valid.
    #[error("Memory configuration is not valid")]
    InvalidMemoryParameters,

    /// Memory backing path contains an interior NUL byte.
    #[error("Memory backing path contains an interior NUL byte")]
    InvalidMemoryPath(#[source] ffi::NulError),

    /// Forbidden operation. Impossible to resize guest memory if it is
    /// backed by user defined memory regions.
    #[error("Impossible to resize guest memory if it is backed by user defined memory regions")]
    InvalidResizeWithMemoryZones,

    /// Forbidden operation. Impossible to resize guest memory below the boot
    /// RAM as it is not removable with virtio-mem.
    #[error("Invalid resize request: desired_size = {0} below boot size = {1}")]
    InvalidResizeBelowBootSize(u64, u64),

    /// It's invalid to try applying a NUMA policy to a memory zone that is
    /// memory mapped with MAP_SHARED.
    #[error(
        "Invalid to try applying a NUMA policy to a memory zone that is memory mapped with MAP_SHARED"
    )]
    InvalidSharedMemoryZoneWithHostNuma,

    /// Failed applying NUMA memory policy.
    #[error("Failed applying NUMA memory policy")]
    ApplyNumaPolicy(#[source] io::Error),

    /// Memory zone identifier is not unique.
    #[error("Memory zone identifier is not unique")]
    DuplicateZoneId,

    /// No virtio-mem resizing handler found.
    #[error("No virtio-mem resizing handler found")]
    MissingVirtioMemHandler,

    /// Unknown memory zone.
    #[error("Unknown memory zone")]
    UnknownMemoryZone,

    /// Invalid size for resizing. Can be anything except 0.
    #[error("Invalid size for resizing. Can be anything except 0")]
    InvalidHotplugSize,

    /// Invalid hotplug method associated with memory zones resizing capability.
    #[error("Invalid hotplug method associated with memory zones resizing capability")]
    InvalidHotplugMethodWithMemoryZones,

    /// Could not find specified memory zone identifier from hash map.
    #[error("Could not find specified memory zone identifier from hash map")]
    MissingZoneIdentifier,

    /// Resizing the memory zone failed.
    #[error("Resizing the memory zone failed")]
    ResizeZone,

    /// Guest address overflow
    #[error("Guest address overflow")]
    GuestAddressOverFlow,

    /// Error opening snapshot file
    #[error("Error opening snapshot file")]
    SnapshotOpen(#[source] io::Error),

    /// Error reading from snapshot file
    #[error("Error reading from snapshot file")]
    SnapshotRead(#[source] io::Error),

    // Error copying snapshot into region
    #[error("Error copying snapshot into region")]
    SnapshotCopy(#[source] GuestMemoryError),

    /// Error mapping snapshot file over guest RAM
    #[error("Error mapping snapshot file over guest RAM")]
    SnapshotMmap(#[source] io::Error),

    /// Failed to allocate MMIO address
    #[error("Failed to allocate MMIO address")]
    AllocateMmioAddress,

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// Failed to create UEFI flash
    #[error("Failed to create UEFI flash")]
    CreateUefiFlash(#[source] GuestRegionError),

    /// Using a directory as a backing file for memory is not supported
    #[error("Using a directory as a backing file for memory is not supported")]
    DirectoryAsBackingFileForMemory,

    /// Failed to stat filesystem
    #[error("Failed to stat filesystem")]
    GetFileSystemBlockSize(#[source] io::Error),

    /// Memory size is misaligned with default page size or its hugepage size
    #[error("Memory size is misaligned with default page size or its hugepage size")]
    MisalignedMemorySize,

    /// Failed to prefault memory
    #[error("Failed to prefault memory")]
    PrefaultMemory(#[source] io::Error),
}

impl From<UffdError> for Error {
    fn from(e: UffdError) -> Self {
        Error::Restore(MigratableError::OnDemandRestore(e))
    }
}

const ENABLE_FLAG: usize = 0;
const INSERTING_FLAG: usize = 1;
const REMOVING_FLAG: usize = 2;
const EJECT_FLAG: usize = 3;

const BASE_OFFSET_LOW: u64 = 0;
const BASE_OFFSET_HIGH: u64 = 0x4;
const LENGTH_OFFSET_LOW: u64 = 0x8;
const LENGTH_OFFSET_HIGH: u64 = 0xC;
const STATUS_OFFSET: u64 = 0x14;
const SELECTION_OFFSET: u64 = 0;

// The MMIO address space size is subtracted with 64k. This is done for the
// following reasons:
//  - Reduce the addressable space size by at least 4k to workaround a Linux
//    bug when the VMM allocates devices at the end of the addressable space
//  - Windows requires the addressable space size to be 64k aligned
fn mmio_address_space_size(phys_bits: u8) -> u64 {
    (1 << phys_bits) - (1 << 16)
}

// The `statfs` function can get information of hugetlbfs, and the hugepage size is in the
// `f_bsize` field.
//
// See: https://github.com/torvalds/linux/blob/v6.3/fs/hugetlbfs/inode.c#L1169
fn statfs_get_bsize(path: &str) -> Result<u64, Error> {
    let path = ffi::CString::new(path).map_err(Error::InvalidMemoryPath)?;
    let mut buf = MaybeUninit::<libc::statfs>::uninit();

    // SAFETY: FFI call with a valid path and buffer
    let ret = unsafe { libc::statfs(path.as_ptr(), buf.as_mut_ptr()) };
    if ret != 0 {
        return Err(Error::GetFileSystemBlockSize(io::Error::last_os_error()));
    }

    // SAFETY: `buf` is valid at this point
    // Because this value is always positive, just convert it directly.
    // Note that the `f_bsize` is `i64` in glibc and `u64` in musl, using `as u64` will be warned
    // by `clippy` on musl target.  To avoid the warning, there should be `as _` instead of
    // `as u64`.
    let bsize = unsafe { (*buf.as_ptr()).f_bsize } as _;
    Ok(bsize)
}

fn memory_zone_get_align_size(zone: &MemoryZoneConfig) -> Result<u64, Error> {
    let page_size = get_page_size();

    // There is no backend file and the `hugepages` is disabled, just use system page size.
    if zone.file.is_none() && !zone.hugepages {
        return Ok(page_size);
    }

    // The `hugepages` is enabled and the `hugepage_size` is specified, just use it directly.
    if let Some(hugepage_size) = zone.hugepage_size
        && zone.hugepages
    {
        return Ok(hugepage_size);
    }

    // There are two scenarios here:
    //  - `hugepages` is enabled but `hugepage_size` is not specified:
    //     Call `statfs` for `/dev/hugepages` for getting the default size of hugepage
    //  - The backing file is specified:
    //     Call `statfs` for the file and get its `f_bsize`.  If the value is larger than the page
    //     size of normal page, just use the `f_bsize` because the file is in a hugetlbfs.  If the
    //     value is less than or equal to the page size, just use the page size.
    let path = zone.file.as_ref().map_or(Ok("/dev/hugepages"), |pathbuf| {
        pathbuf.to_str().ok_or(Error::InvalidMemoryParameters)
    })?;

    let align_size = cmp::max(page_size, statfs_get_bsize(path)?);

    Ok(align_size)
}

#[inline]
fn align_down<T>(val: T, align: T) -> T
where
    T: BitAnd<Output = T> + Not<Output = T> + Sub<Output = T> + From<u8>,
{
    val & !(align - 1u8.into())
}

#[inline]
pub(crate) fn is_aligned<T>(val: T, align: T) -> bool
where
    T: BitAnd<Output = T> + Sub<Output = T> + From<u8> + PartialEq,
{
    (val & (align - 1u8.into())) == 0u8.into()
}

impl BusDevice for MemoryManager {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        if self.selected_slot < self.hotplug_slots.len() {
            let state = &self.hotplug_slots[self.selected_slot];
            if matches!(
                offset,
                BASE_OFFSET_LOW | BASE_OFFSET_HIGH | LENGTH_OFFSET_LOW | LENGTH_OFFSET_HIGH
            ) && data.len() != 4
            {
                warn!(
                    "Invalid sized read ({}) of memory manager register {offset:#x}",
                    data.len()
                );
                return;
            }
            match offset {
                BASE_OFFSET_LOW => {
                    data.copy_from_slice(&state.base.to_le_bytes()[..4]);
                }
                BASE_OFFSET_HIGH => {
                    data.copy_from_slice(&state.base.to_le_bytes()[4..]);
                }
                LENGTH_OFFSET_LOW => {
                    data.copy_from_slice(&state.length.to_le_bytes()[..4]);
                }
                LENGTH_OFFSET_HIGH => {
                    data.copy_from_slice(&state.length.to_le_bytes()[4..]);
                }
                STATUS_OFFSET => {
                    // The Linux kernel, quite reasonably, doesn't zero the memory it gives us.
                    data.fill(0);
                    if state.active {
                        data[0] |= 1 << ENABLE_FLAG;
                    }
                    if state.inserting {
                        data[0] |= 1 << INSERTING_FLAG;
                    }
                    if state.removing {
                        data[0] |= 1 << REMOVING_FLAG;
                    }
                }
                _ => {
                    debug!("Unexpected offset for accessing memory manager device: {offset:#}");
                }
            }
        } else {
            warn!("Out of range memory slot: {}", self.selected_slot);
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        match offset {
            SELECTION_OFFSET => {
                self.selected_slot = usize::from(data[0]);
            }
            STATUS_OFFSET => {
                if self.selected_slot < self.hotplug_slots.len() {
                    let state = &mut self.hotplug_slots[self.selected_slot];
                    // The ACPI code writes back a 1 to acknowledge the insertion
                    if (data[0] & (1 << INSERTING_FLAG) == 1 << INSERTING_FLAG) && state.inserting {
                        state.inserting = false;
                    }
                    // Ditto for removal
                    if (data[0] & (1 << REMOVING_FLAG) == 1 << REMOVING_FLAG) && state.removing {
                        state.removing = false;
                    }
                    // Trigger removal of "DIMM"
                    if data[0] & (1 << EJECT_FLAG) == 1 << EJECT_FLAG {
                        warn!("Ejection of memory not currently supported");
                    }
                } else {
                    warn!("Out of range memory slot: {}", self.selected_slot);
                }
            }
            _ => {
                debug!("Unexpected offset for accessing memory manager device: {offset:#}");
            }
        }
        None
    }
}

/// Memory range policy.
#[derive(Clone, Copy)]
pub enum MemoryRangePolicy {
    /// Send every region in full.
    Full,
    /// Send every region in full, except those already persisted through a
    /// shared, hardlinked backing file.
    SkipPersisted,
    /// Send only the populated ranges of each region, skipping holes.
    Sparse,
}

impl MemoryManager {
    /// Creates all memory regions based on the available RAM ranges defined
    /// by `ram_regions`, and based on the description of the memory zones.
    /// In practice, this function can perform multiple memory mappings of the
    /// same backing file if there's a hole in the address space between two
    /// RAM ranges.
    ///
    /// One example might be ram_regions containing 2 regions (0-3G and 4G-6G)
    /// and zones containing two zones (size 1G and size 4G).
    ///
    /// This function will create 3 resulting memory regions:
    /// - First one mapping entirely the first memory zone on 0-1G range
    /// - Second one mapping partially the second memory zone on 1G-3G range
    /// - Third one mapping partially the second memory zone on 4G-6G range
    ///
    /// Also, all memory regions are page-size aligned (e.g. their sizes must
    /// be multiple of page-size), which may leave an additional hole in the
    /// address space when hugepage is used.
    fn create_memory_regions_from_zones(
        ram_regions: &[(GuestAddress, usize)],
        zones: &[MemoryZoneConfig],
        thp: bool,
        vm: &Arc<dyn hypervisor::Vm>,
        slot_allocator: &Arc<MemorySlotAllocator>,
        log_dirty: bool,
    ) -> Result<(Vec<Arc<GuestRegion>>, MemoryZones), Error> {
        let mut zone_iter = zones.iter();
        let mut mem_regions = Vec::new();
        let mut zone = zone_iter.next().ok_or(Error::MissingMemoryZones)?;
        let mut zone_align_size = memory_zone_get_align_size(zone)?;
        let mut zone_offset = 0u64;
        let mut memory_zones = HashMap::new();

        if !is_aligned(zone.size, zone_align_size) {
            return Err(Error::MisalignedMemorySize);
        }

        // Add zone id to the list of memory zones.
        memory_zones.insert(
            zone.id.clone(),
            MemoryZone::new(zone.shared, zone.hugepages, zone_align_size, zone.mergeable),
        );

        for ram_region in ram_regions.iter() {
            let mut ram_region_offset = 0;
            let mut exit = false;

            loop {
                let mut ram_region_consumed = false;
                let mut pull_next_zone = false;

                let ram_region_available_size =
                    align_down(ram_region.1 as u64 - ram_region_offset, zone_align_size);
                if ram_region_available_size == 0 {
                    break;
                }
                let zone_sub_size = zone.size - zone_offset;

                let file_offset = zone_offset;
                let region_start = ram_region
                    .0
                    .checked_add(ram_region_offset)
                    .ok_or(Error::GuestAddressOverFlow)?;
                let region_size = if zone_sub_size <= ram_region_available_size {
                    if zone_sub_size == ram_region_available_size {
                        ram_region_consumed = true;
                    }

                    ram_region_offset += zone_sub_size;
                    pull_next_zone = true;

                    zone_sub_size
                } else {
                    zone_offset += ram_region_available_size;
                    ram_region_consumed = true;

                    ram_region_available_size
                };

                info!(
                    "create ram region for zone {}, region_start: {:#x}, region_size: {:#x}",
                    zone.id,
                    region_start.raw_value(),
                    region_size
                );
                let region = MemoryManager::create_ram_region(
                    &zone.file,
                    file_offset,
                    region_start,
                    region_size as usize,
                    zone.reserve.unwrap_or(zone.hugepages),
                    zone.shared,
                    zone.hugepages,
                    zone.hugepage_size,
                    zone.host_numa_node,
                    None,
                    thp,
                    Arc::clone(vm),
                    Arc::clone(slot_allocator),
                    zone.mergeable,
                    log_dirty,
                    hypervisor::MemoryVisibility::Private,
                )?;

                // Add region to the list of regions associated with the
                // current memory zone.
                if let Some(memory_zone) = memory_zones.get_mut(&zone.id) {
                    memory_zone.regions.push(Arc::clone(&region));
                }

                mem_regions.push(region);

                if pull_next_zone {
                    // Get the next zone and reset the offset.
                    zone_offset = 0;
                    if let Some(z) = zone_iter.next() {
                        zone = z;
                    } else {
                        exit = true;
                        break;
                    }
                    zone_align_size = memory_zone_get_align_size(zone)?;
                    if !is_aligned(zone.size, zone_align_size) {
                        return Err(Error::MisalignedMemorySize);
                    }

                    // Check if zone id already exist. In case it does, throw
                    // an error as we need unique identifiers. Otherwise, add
                    // the new zone id to the list of memory zones.
                    if memory_zones.contains_key(&zone.id) {
                        error!(
                            "Memory zone identifier '{}' found more than once. \
                            It must be unique",
                            zone.id,
                        );
                        return Err(Error::DuplicateZoneId);
                    }
                    memory_zones.insert(
                        zone.id.clone(),
                        MemoryZone::new(
                            zone.shared,
                            zone.hugepages,
                            zone_align_size,
                            zone.mergeable,
                        ),
                    );
                }

                if ram_region_consumed {
                    break;
                }
            }

            if exit {
                break;
            }
        }

        Ok((mem_regions, memory_zones))
    }

    fn prefault_regions_from_zones(
        zones: &[MemoryZoneConfig],
        memory_zones: &MemoryZones,
        prefault: Option<bool>,
    ) -> Result<Vec<prefault::PrefaultRegion>, Error> {
        let mut prefault_regions = Vec::new();
        for zone in zones {
            if !prefault.unwrap_or(zone.prefault) {
                continue;
            }
            let Some(memory_zone) = memory_zones.get(&zone.id) else {
                continue;
            };

            let page_size =
                Self::get_prefault_align_size(&zone.file, zone.hugepages, zone.hugepage_size)?
                    as usize;
            for region in &memory_zone.regions {
                prefault_regions.push(prefault::PrefaultRegion {
                    addr: region.as_ptr() as usize,
                    size: region.len() as usize,
                    page_size,
                    host_numa_node: zone.host_numa_node,
                });
            }

            if let Some(virtio_mem_zone) = &memory_zone.virtio_mem_zone {
                let page_size =
                    Self::get_prefault_align_size(&None, zone.hugepages, zone.hugepage_size)?
                        as usize;
                prefault_regions.push(prefault::PrefaultRegion {
                    addr: virtio_mem_zone.region.as_ptr() as usize,
                    size: virtio_mem_zone.region.len() as usize,
                    page_size,
                    host_numa_node: zone.host_numa_node,
                });
            }
        }
        Ok(prefault_regions)
    }

    // Restore both GuestMemoryBackend regions along with MemoryZone zones.
    fn restore_memory_regions_and_zones(
        guest_ram_mappings: &[GuestRamMapping],
        zones_config: &[MemoryZoneConfig],
        mut existing_memory_files: HashMap<u32, File>,
        thp: bool,
        vm: &Arc<dyn hypervisor::Vm>,
        slot_allocator: &Arc<MemorySlotAllocator>,
        log_dirty: bool,
    ) -> Result<(Vec<Arc<GuestRegion>>, MemoryZones), Error> {
        let mut memory_regions = Vec::new();
        let mut memory_zones = HashMap::new();

        for zone_config in zones_config {
            let zone_page_size = memory_zone_get_align_size(zone_config)?;
            memory_zones.insert(
                zone_config.id.clone(),
                MemoryZone::new(
                    zone_config.shared,
                    zone_config.hugepages,
                    zone_page_size,
                    zone_config.mergeable,
                ),
            );
        }

        for guest_ram_mapping in guest_ram_mappings {
            for zone_config in zones_config {
                if guest_ram_mapping.zone_id == zone_config.id {
                    let region = MemoryManager::create_ram_region(
                        if guest_ram_mapping.virtio_mem {
                            &None
                        } else {
                            &zone_config.file
                        },
                        guest_ram_mapping.file_offset,
                        GuestAddress(guest_ram_mapping.gpa),
                        guest_ram_mapping.size as usize,
                        zone_config.reserve.unwrap_or(zone_config.hugepages),
                        zone_config.shared,
                        zone_config.hugepages,
                        zone_config.hugepage_size,
                        zone_config.host_numa_node,
                        existing_memory_files.remove(&guest_ram_mapping.slot),
                        thp,
                        Arc::clone(vm),
                        Arc::clone(slot_allocator),
                        zone_config.mergeable,
                        log_dirty,
                        hypervisor::MemoryVisibility::Private,
                    )?;
                    memory_regions.push(Arc::clone(&region));
                    if let Some(memory_zone) = memory_zones.get_mut(&guest_ram_mapping.zone_id) {
                        if guest_ram_mapping.virtio_mem {
                            let hotplugged_size = zone_config.hotplugged_size.unwrap_or(0);
                            let region_size = region.len();
                            memory_zone.virtio_mem_zone = Some(VirtioMemZone {
                                region,
                                virtio_device: None,
                                hotplugged_size,
                                hugepages: zone_config.hugepages,
                                blocks_state: Arc::new(Mutex::new(BlocksState::new(region_size))),
                            });
                        } else {
                            memory_zone.regions.push(region);
                        }
                    }
                }
            }
        }

        memory_regions.sort_by_key(|x| x.start_addr());

        Ok((memory_regions, memory_zones))
    }

    fn fill_saved_regions(
        &mut self,
        file_path: PathBuf,
        saved_regions: &MemoryRangeTable,
    ) -> Result<(), Error> {
        Self::copy_saved_regions(&self.guest_memory.memory(), file_path, saved_regions)
    }

    fn copy_saved_regions(
        guest_memory: &GuestMemory,
        file_path: PathBuf,
        saved_regions: &MemoryRangeTable,
    ) -> Result<(), Error> {
        // Open (read only) the snapshot file.
        let mut memory_file = OpenOptions::new()
            .read(true)
            .open(file_path)
            .map_err(Error::SnapshotOpen)?;

        let mut file_cursor: u64 = 0;

        for range in saved_regions.ranges() {
            let end = file_cursor + range.length;

            // First call doubles as a SEEK_HOLE-support probe. On error,
            // take the dense path which seeks-and-streams sequentially.
            match next_data_extent(memory_file.as_fd(), file_cursor, end) {
                Ok(mut next) => {
                    while let Some((data_off, ext_len)) = next {
                        debug_assert!(data_off >= file_cursor);
                        let in_region = data_off
                            .checked_sub(file_cursor)
                            .expect("extent precedes file_cursor");
                        memory_file
                            .seek(SeekFrom::Start(data_off))
                            .map_err(Error::SnapshotRead)?;
                        let mut done: u64 = 0;
                        while done < ext_len {
                            let n = guest_memory
                                .read_volatile_from(
                                    GuestAddress(range.gpa + in_region + done),
                                    &mut memory_file,
                                    (ext_len - done) as usize,
                                )
                                .map_err(Error::SnapshotCopy)?;
                            if n == 0 {
                                return Err(Error::SnapshotRead(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "read_volatile_from returned 0 inside data extent",
                                )));
                            }
                            done += n as u64;
                        }
                        next = next_data_extent(memory_file.as_fd(), data_off + ext_len, end)
                            .map_err(Error::SnapshotRead)?;
                    }
                }
                Err(_) => {
                    memory_file
                        .seek(SeekFrom::Start(file_cursor))
                        .map_err(Error::SnapshotRead)?;
                    let mut offset: u64 = 0;
                    // Manual partial-read loop preserves the workaround for
                    // https://github.com/rust-vmm/vm-memory/issues/174
                    loop {
                        let bytes_read = guest_memory
                            .read_volatile_from(
                                GuestAddress(range.gpa + offset),
                                &mut memory_file,
                                (range.length - offset) as usize,
                            )
                            .map_err(Error::SnapshotCopy)?;
                        if bytes_read == 0 {
                            return Err(Error::SnapshotRead(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Memory snapshot file is shorter than the saved range",
                            )));
                        }
                        offset += bytes_read as u64;
                        if offset == range.length {
                            break;
                        }
                    }
                }
            }

            file_cursor = end;
        }

        Ok(())
    }

    // Restore guest memory by mapping the snapshot file copy-on-write over
    // the anonymous guest mappings — before any KVM memslot or device
    // consumes them, so overlay identity concerns do not apply. Falls back
    // to the eager copy whenever a range cannot be mapped safely. The
    // snapshot file must remain on disk for the VM lifetime.
    fn mmap_cow_saved_regions(
        &mut self,
        file_path: PathBuf,
        saved_regions: &MemoryRangeTable,
    ) -> Result<(), Error> {
        let Some(memory_file) = Self::cow_map_saved_regions(
            &self.guest_memory.memory(),
            &self.memory_zones,
            self.thp,
            file_path,
            saved_regions,
        )?
        else {
            return Ok(());
        };
        // Landlock applies after the restore, so the pagemap is opened here.
        self.cow_source = match PageMap::open() {
            Ok(pagemap) => Some(CowSource {
                file: memory_file,
                ranges: saved_regions.clone(),
                pagemap,
            }),
            Err(e) => {
                warn!("Restore (mode=copyonwrite): snapshots will write all guest memory: {e}");
                None
            }
        };
        Ok(())
    }

    // Returns the snapshot file when the ranges were mapped from it, or None
    // when the restore fell back to the eager copy.
    fn cow_map_saved_regions(
        guest_memory: &GuestMemory,
        memory_zones: &MemoryZones,
        thp: bool,
        file_path: PathBuf,
        saved_regions: &MemoryRangeTable,
    ) -> Result<Option<File>, Error> {
        // Overlapping saved ranges land here too. The copy goes in table
        // order, so where ranges overlap a later range's data replaces an
        // earlier one's. Where SEEK_DATA works on the snapshot file, the
        // copy writes only each range's data, and a later range's hole
        // leaves the earlier range's data in place; where it does not, each
        // range is copied whole, and a later range's hole overwrites the
        // earlier range's data with zeroes.
        if !is_restore_cow_compatible(guest_memory, saved_regions) {
            info!("Restore (mode=copyonwrite): guest RAM unsuitable, falling back to copy");
            Self::copy_saved_regions(guest_memory, file_path, saved_regions)?;
            return Ok(None);
        }
        if saved_ranges_in_virtio_mem(memory_zones, saved_regions) {
            info!("Restore (mode=copyonwrite): plugged virtio-mem blocks, falling back to copy");
            Self::copy_saved_regions(guest_memory, file_path, saved_regions)?;
            return Ok(None);
        }
        let memory_file = OpenOptions::new()
            .read(true)
            .open(file_path)
            .map_err(Error::SnapshotOpen)?;
        // A range mapped past EOF faults SIGBUS at run time, not restore time.
        let mapped_len: u64 = saved_regions.ranges().iter().map(|r| r.length).sum();
        let file_len = memory_file.metadata().map_err(Error::SnapshotOpen)?.len();
        if file_len < mapped_len {
            return Err(Error::SnapshotMmap(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "snapshot memory file is shorter than the saved ranges",
            )));
        }
        do_mmap_cow_saved_regions(guest_memory, &memory_file, saved_regions, thp)?;
        Ok(Some(memory_file))
    }

    /// Restore guest memory using userfaultfd for lazy demand paging.
    ///
    /// Instead of reading the entire snapshot into guest RAM upfront (which
    /// blocks restore for hundreds of milliseconds at multi-GB sizes), this
    /// registers the guest memory regions with a userfaultfd. A background
    /// thread handles page faults by reading the corresponding page from the
    /// snapshot file and copying it into guest memory via `UFFDIO_COPY`.
    ///
    /// This preserves the original memory mapping type (anonymous or shared),
    /// making it compatible with VFIO device passthrough and shared-memory
    /// guest RAM.
    ///
    /// Fails the restore if UFFD setup cannot be completed successfully.
    ///
    /// The handler thread keeps the snapshot file open while lazy restore
    /// is active. The file must remain available until the VM is shut down or
    /// all faulted pages have been served.
    ///
    /// With `copy_on_access`, nothing is copied in the background: a page is
    /// copied only when first accessed, the handler serves faults until the
    /// VM is shut down, and the snapshot file stays open for that long.
    fn restore_by_uffd(
        &mut self,
        file_path: &Path,
        saved_regions: &MemoryRangeTable,
        background_fetch_pages: bool,
        exit_evt: &EventFd,
        copy_on_access: bool,
    ) -> Result<(), Error> {
        let mut file_offset: u64 = 0;

        let snapshot_file = File::open(file_path).map_err(Error::SnapshotOpen)?;
        // As copy-on-write does: a page past EOF would fail its read while
        // the VM runs, which stops the VM, so refuse the restore now.
        check_snapshot_file_covers_ranges(&snapshot_file, saved_regions)?;
        let source: Box<dyn UffdMemorySource> = Box::new(
            FileUffdMemorySource::for_snapshot(
                snapshot_file.try_clone().map_err(Error::SnapshotOpen)?,
                file_path,
            )
            .map_err(Error::SnapshotOpen)?,
        );

        let Some(uffd) = self.prepare_uffd(
            saved_regions,
            |r| {
                let o = file_offset;
                file_offset += r.length;
                o
            },
            source.requires_uffd_minor_mode(),
        )?
        else {
            return Ok(());
        };
        // Per-range bitmap tracking which pages have been populated by the
        // on-demand fault handler. Lets the prefault cursor skip them without
        // doing a wasted file read + UFFDIO_COPY.
        let served_bitmap: Vec<AtomicBitmap> = uffd
            .ranges()
            .iter()
            .map(|r| {
                AtomicBitmap::new(
                    r.length as usize,
                    NonZeroUsize::new(r.page_size as usize).unwrap(),
                )
            })
            .collect();

        if copy_on_access {
            // No prefault, so holes stay unserved: a hole is then saved from
            // the snapshot file (as a hole) rather than read through guest
            // memory, which would fault it in.
            self.spawn_uffd_handler(
                uffd,
                None,
                served_bitmap.into(),
                source,
                exit_evt,
                UffdServing::CopyOnAccess {
                    source: snapshot_file,
                },
            )?;
            info!("UFFD restore: copy-on-access restore enabled");
            return Ok(());
        }

        // For sparse files, we mark holes as served pages so we don't prefault them.
        for (range, served) in uffd.ranges().iter().zip(&served_bitmap) {
            let end = range.source_offset + range.length;
            let mut file_cursor = range.source_offset;
            while let Ok(next) = next_data_extent(snapshot_file.as_fd(), file_cursor, end) {
                let (data_off, ext_len) = next.unwrap_or((end, 0));
                let hole_start =
                    (file_cursor - range.source_offset).next_multiple_of(range.page_size);
                let hole_end = align_down(data_off - range.source_offset, range.page_size);
                if hole_end > hole_start {
                    served.set_addr_range(hole_start as usize, (hole_end - hole_start) as usize);
                }
                if next.is_none() {
                    break;
                }
                file_cursor = data_off + ext_len;
            }
        }

        self.spawn_uffd_handler(
            uffd,
            None,
            served_bitmap.into(),
            source,
            exit_evt,
            UffdServing::OnDemand {
                background_fetch_pages,
            },
        )?;
        info!("UFFD restore: demand-paged restore enabled");
        Ok(())
    }

    /// Register UFFD and spawn the handler that serves faults over `socket`.
    /// No-op when there are no regions.
    pub(crate) fn start_postcopy_serving(
        &mut self,
        saved_regions: &MemoryRangeTable,
        shared_backing: bool,
        background_fetch_pages: bool,
        socket: SocketStream,
        exit_evt: &EventFd,
    ) -> Result<(), Error> {
        // Make every fault a small request/response round-trip.
        socket.set_nodelay(true).map_err(UffdError::SetSocket)?;
        let socket_fd = socket
            .as_fd()
            .try_clone_to_owned()
            .map_err(UffdError::SetSocket)?;
        let source: Box<dyn UffdMemorySource> =
            Box::new(SocketUffdMemorySource::new(socket, shared_backing));

        // PageFault uses the GPA as the page identifier on the wire.
        let Some(uffd) =
            self.prepare_uffd(saved_regions, |r| r.gpa, source.requires_uffd_minor_mode())?
        else {
            return Ok(());
        };

        let served_bitmap: Vec<AtomicBitmap> = uffd
            .ranges()
            .iter()
            .map(|r| {
                AtomicBitmap::new(
                    r.length as usize,
                    NonZeroUsize::new(r.page_size as usize).unwrap(),
                )
            })
            .collect();
        info!("UFFD: postcopy background prefault {background_fetch_pages}");
        self.spawn_uffd_handler(
            uffd,
            Some(socket_fd),
            served_bitmap.into(),
            source,
            exit_evt,
            UffdServing::OnDemand {
                background_fetch_pages,
            },
        )
    }

    /// Create a UFFD fd and register every range.
    fn prepare_uffd<F>(
        &mut self,
        saved_regions: &MemoryRangeTable,
        mut source_offset_for: F,
        uffd_requires_minor_mode: bool,
    ) -> Result<Option<Uffd>, Error>
    where
        F: FnMut(&MemoryRange) -> u64,
    {
        if saved_regions.is_empty() {
            return Ok(None);
        }

        let guest_memory = self.guest_memory.memory();
        let required_uffd_features = self.required_uffd_features(uffd_requires_minor_mode);

        let base_page_size = get_page_size();

        info!(
            "UFFD: registering {} region(s) for demand paging",
            saved_regions.ranges().len()
        );

        if saved_regions.ranges().iter().any(|range| {
            !range.gpa.is_multiple_of(base_page_size)
                || !range.length.is_multiple_of(base_page_size)
        }) {
            return Err(UffdError::UnalignedRanges.into());
        }

        let uffd_fd = uffd::create(required_uffd_features).map_err(UffdError::Create)?;

        let mut handler_ranges: Vec<UffdRange> = Vec::new();

        for range in saved_regions.ranges() {
            // The range must not span across multiple guest RAM regions
            let host_addr = guest_memory
                .get_slice(GuestAddress(range.gpa), range.length as usize)
                .and_then(|_| guest_memory.get_host_address(GuestAddress(range.gpa)))
                .map_err(|e| UffdError::GpaTranslation {
                    gpa: range.gpa,
                    source: e,
                })? as u64;

            let ioctls = uffd::register(
                uffd_fd.as_fd(),
                host_addr,
                range.length,
                uffd_requires_minor_mode,
            )
            .map_err(|e| UffdError::Register {
                addr: host_addr,
                len: range.length,
                source: e,
            })?;

            let required_ioctls = if uffd_requires_minor_mode {
                userfaultfd::UFFD_API_RANGE_IOCTLS_MINOR
            } else {
                userfaultfd::UFFD_API_RANGE_IOCTLS_BASIC
            };

            if ioctls & required_ioctls != required_ioctls {
                return Err(UffdError::MissingIoctlSupport {
                    addr: host_addr,
                    len: range.length,
                }
                .into());
            }

            let range_page_size = self
                .memory_zones
                .values()
                .find_map(|zone| zone.backing_page_size_for_gpa(range.gpa))
                .unwrap_or(base_page_size);

            handler_ranges.push(UffdRange {
                host_addr,
                length: range.length,
                source_offset: source_offset_for(range),
                page_size: range_page_size,
            });
        }

        Ok(Some(
            Uffd::new(uffd_fd, handler_ranges.into(), Box::new([])).map_err(UffdError::Create)?,
        ))
    }

    /// Spawn the UFFD handler thread that resolves faults through `source`.
    fn spawn_uffd_handler(
        &mut self,
        uffd: Uffd,
        fault_socket_fd: Option<OwnedFd>,
        served_bitmap: Arc<[AtomicBitmap]>,
        source: Box<dyn UffdMemorySource>,
        exit_evt: &EventFd,
        serving: UffdServing,
    ) -> Result<(), Error> {
        info!(
            "UFFD: spawning handler for {} region(s)",
            uffd.ranges().len()
        );

        let serve_lock = Arc::new(Mutex::new(()));
        let (background_fetch_pages, private_zeroes, copy_on_access) = match serving {
            UffdServing::OnDemand {
                background_fetch_pages,
            } => (background_fetch_pages, false, None),
            UffdServing::CopyOnAccess { source } => (
                false,
                true,
                Some(CopyOnAccessPages {
                    source,
                    ranges: uffd.ranges().into(),
                    served: Arc::clone(&served_bitmap),
                    serve_lock: Arc::clone(&serve_lock),
                }),
            ),
        };

        let stop_event = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFdFail)?;
        let thread_stop_event = stop_event.try_clone().map_err(Error::EventFdFail)?;
        let thread_exit_evt = exit_evt.try_clone().map_err(Error::EventFdFail)?;
        let panic_exit_evt = exit_evt.try_clone().map_err(Error::EventFdFail)?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let ranges = Box::from(uffd.ranges());
        let uffd_registry = Arc::new(UffdRegistry {
            added_uffds: Mutex::new(vec![(VMM_UFFD_ID.to_string(), uffd)]),
            added_uffd_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFdFail)?,
            done: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFdFail)?,
            ranges,
        });
        let thread_uffd_registry = Arc::clone(&uffd_registry);
        let handle = thread::Builder::new()
            .name("uffd-handler".to_string())
            .spawn(move || {
                panic::catch_unwind(panic::AssertUnwindSafe(move || {
                    let mut result = Self::uffd_handler_loop(
                        &thread_uffd_registry,
                        &thread_stop_event,
                        &thread_exit_evt,
                        source,
                        served_bitmap,
                        &serve_lock,
                        &ready_tx,
                        background_fetch_pages,
                        private_zeroes,
                    );

                    if result.is_err() && thread_stop_event.read().is_ok() {
                        // Error during shutdown is expected
                        result = Ok(());
                    }

                    if let Err(e) = &result {
                        error!("UFFD handler exited with error: {e}");
                        thread_exit_evt.write(1).ok();
                    }

                    result_tx.send(result).ok();
                }))
                .map_err(|_| {
                    error!("uffd-handler thread panicked");
                    panic_exit_evt.write(1).ok();
                })
                .ok();
            })
            .map_err(UffdError::SpawnThread)?;

        if ready_rx.recv().is_err() {
            handle.join().ok();
            return Err(UffdError::HandlerStartup.into());
        }

        if let Ok(Err(e)) = result_rx.try_recv() {
            handle.join().ok();
            return Err(UffdError::HandlerFailed(e).into());
        }

        self.uffd_handler = Some(UffdHandler {
            stop_event,
            result_rx,
            handle,
            fault_socket_fd,
            uffd_registry,
            copy_on_access,
        });

        Ok(())
    }

    fn required_uffd_features(&self, uffd_requires_minor_mode: bool) -> u64 {
        let mut features = 0u64;
        if self.memory_zones.values().any(|z| z.shared || !z.hugepages) {
            features |= userfaultfd::UFFD_FEATURE_MISSING_SHMEM;
            if uffd_requires_minor_mode {
                features |= userfaultfd::UFFD_FEATURE_MINOR_SHMEM;
            }
        }
        if self.memory_zones.values().any(|z| z.hugepages) {
            features |= userfaultfd::UFFD_FEATURE_MISSING_HUGETLBFS;
            if uffd_requires_minor_mode {
                features |= userfaultfd::UFFD_FEATURE_MINOR_HUGETLBFS;
            }
        }
        features
    }

    /// Stop the UFFD handler, if any, and wait for it to exit, closing the
    /// userfaultfd and the restore source.
    fn stop_uffd_handler(&mut self) {
        if let Some(uffd_handler) = self.uffd_handler.take() {
            uffd_handler.stop_event.write(1).ok();
            if let Some(fd) = &uffd_handler.fault_socket_fd {
                // SAFETY: fd is a valid owned fd for the duration of this call.
                unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_RDWR) };
            }
            uffd_handler.handle.join().ok();

            match uffd_handler.result_rx.try_recv() {
                Ok(Err(e)) => error!("UFFD handler terminated with error: {e}"),
                Err(mpsc::TryRecvError::Disconnected) => {
                    warn!("UFFD handler terminated unexpectedly (possible panic)");
                }
                _ => {}
            }
        }
    }

    pub(crate) fn uffd_registry(&self) -> Option<Arc<UffdRegistry>> {
        let uffd_handler = self.uffd_handler.as_ref()?;
        Some(Arc::clone(&uffd_handler.uffd_registry))
    }

    /// True while an on-demand (UFFD) restore is still faulting in guest RAM.
    /// A copy-on-access restore never completes and is not counted: its
    /// snapshot writer saves the pages not faulted in from the restore source.
    pub fn restoring(&self) -> bool {
        self.uffd_handler
            .as_ref()
            .is_some_and(|h| h.copy_on_access.is_none() && !h.uffd_registry.is_done())
    }

    /// True when guest RAM was restored copy-on-access: part of it may still
    /// be only in the snapshot it was restored from, for the VM's lifetime.
    pub fn copy_on_access(&self) -> bool {
        self.uffd_handler
            .as_ref()
            .is_some_and(|h| h.copy_on_access.is_some())
    }

    /// Poison a page that can no longer be restored. Exits if that's not
    /// possible.
    fn uffd_poison_page(
        uffd_fd: BorrowedFd<'_>,
        range: &UffdRange,
        page_idx: u64,
    ) -> Result<(), io::Error> {
        let page_addr = range.page_addr(page_idx);
        match uffd::poison(uffd_fd, page_addr, range.page_size) {
            Ok(()) => Ok(()),
            // Already present or poisoned by an earlier fault on that page.
            // Wake any blocked threads.
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                uffd::wake(uffd_fd, page_addr, range.page_size)
            }
            Err(e) => {
                error!("UFFD handler cannot poison unrestored guest memory: {e}");
                process::exit(1);
            }
        }
    }

    /// Serve UFFD faults from every userfaultfd received through
    /// `uffd_registry` via `source`, prefaulting one page per idle iteration
    /// through the first one, which `uffd_registry` must hold already. Once
    /// `source` fails, poison each faulted page instead.
    ///
    /// A userfaultfd received with the id of an earlier one replaces it. Once
    /// all pages are present, `uffd_registry.done` is written.
    ///
    /// With `private_zeroes`, a page faulted again after a discard is
    /// resolved with a zeroed private copy rather than the zero page every
    /// process shares. `serve_lock` is held while a fault is resolved and
    /// its served bit updated.
    #[expect(clippy::needless_pass_by_value, clippy::too_many_arguments)]
    fn uffd_handler_loop(
        uffd_registry: &UffdRegistry,
        stop_event: &EventFd,
        exit_evt: &EventFd,
        mut source: Box<dyn UffdMemorySource>,
        served_bitmap: Arc<[AtomicBitmap]>,
        serve_lock: &Mutex<()>,
        ready_tx: &SyncSender<()>,
        background_fetch_pages: bool,
        private_zeroes: bool,
    ) -> Result<(), io::Error> {
        let mut uffds = uffd_registry.drain_added_uffds();
        assert!(!uffds.is_empty());
        let (_, vmm_uffd) = &uffds[0];
        let ranges = vmm_uffd.ranges();

        let total_pages: u64 = ranges.iter().map(UffdRange::num_pages).sum();
        let mut pages_served: u64 = 0;
        let mut pages_prefaulted: u64 = 0;

        let pages_loading: Mutex<HashSet<(usize, u64)>> = Mutex::new(HashSet::new());

        let zero_buf = uffd::allocate_zero_buffer(
            ranges.iter().map(|r| r.page_size).max().unwrap_or(0) as usize,
        );

        let mut prefault_active = background_fetch_pages && !ranges.is_empty();
        let mut source_failed = false;
        let mut range_idx = 0;
        let mut page_idx = 0;
        let prefault_start = time::Instant::now();

        const EVENT_STOP: u64 = u64::MAX;
        const EVENT_ADDED_UFFD: u64 = u64::MAX - 1;

        let epoll_fd = epoll::create(true).map_err(io::Error::other)?;
        // SAFETY: epoll_fd is valid and owned by this scope.
        let _epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            stop_event.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, EVENT_STOP),
        )
        .map_err(io::Error::other)?;

        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            uffd_registry.added_uffd_evt.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, EVENT_ADDED_UFFD),
        )
        .map_err(io::Error::other)?;

        for (idx, (_, uffd)) in uffds.iter().enumerate() {
            epoll::ctl(
                epoll_fd,
                epoll::ControlOptions::EPOLL_CTL_ADD,
                uffd.fd().as_raw_fd(),
                epoll::Event::new(epoll::Events::EPOLLIN, idx as u64),
            )
            .map_err(io::Error::other)?;
        }

        ready_tx.send(()).ok();

        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); uffds.len() + 2];
        loop {
            // Block only when prefault is done; otherwise poll non-blocking
            // so we can advance prefault between faults.
            let timeout = if prefault_active { 0 } else { -1 };
            let num_events = match epoll::wait(epoll_fd, timeout, &mut events) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };

            // Check the entire batch before handling UFFD events so a pending
            // stop cannot be delayed by a blocking page resolution.
            if events
                .iter()
                .take(num_events)
                .any(|event| event.data == EVENT_STOP)
            {
                stop_event.read().ok();
                info!("UFFD handler: received stop event, exiting");
                return Ok(());
            }

            if events
                .iter()
                .take(num_events)
                .any(|event| event.data == EVENT_ADDED_UFFD)
            {
                uffd_registry.added_uffd_evt.read().ok();
                for (id, uffd) in uffd_registry.drain_added_uffds() {
                    let idx =
                        if let Some(idx) = uffds.iter().position(|(uffd_id, _)| *uffd_id == id) {
                            // Its process remapped guest memory, as on a device reset
                            epoll::ctl(
                                epoll_fd,
                                epoll::ControlOptions::EPOLL_CTL_DEL,
                                uffds[idx].1.fd().as_raw_fd(),
                                epoll::Event::new(epoll::Events::empty(), 0),
                            )
                            .map_err(io::Error::other)?;
                            uffds[idx].1 = uffd;
                            idx
                        } else {
                            uffds.push((id, uffd));
                            uffds.len() - 1
                        };
                    epoll::ctl(
                        epoll_fd,
                        epoll::ControlOptions::EPOLL_CTL_ADD,
                        uffds[idx].1.fd().as_raw_fd(),
                        epoll::Event::new(epoll::Events::EPOLLIN, idx as u64),
                    )
                    .map_err(io::Error::other)?;
                }
                events.resize(
                    uffds.len() + 2,
                    epoll::Event::new(epoll::Events::empty(), 0),
                );
                continue;
            }

            let (_, vmm_uffd) = &uffds[0];
            let ranges = vmm_uffd.ranges();

            let mut ready_uffd = None;
            for event in events.iter().take(num_events) {
                let idx = event.data as usize;
                let evt_flags = event.events;

                if (evt_flags & epoll::Events::EPOLLIN.bits()) != 0 {
                    ready_uffd = Some(idx);
                    break;
                }
            }

            if let Some(idx) = ready_uffd {
                let (_, fault_uffd) = &uffds[idx];
                // SAFETY: UffdMsg is a plain repr(C) struct, safe to zero-init.
                let mut msg: uffd::UffdMsg = unsafe { zeroed() };
                // SAFETY: reading a uffd_msg-sized struct from the valid uffd fd.
                let n = unsafe {
                    libc::read(
                        fault_uffd.fd().as_raw_fd(),
                        (&raw mut msg).cast(),
                        size_of::<uffd::UffdMsg>(),
                    )
                };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        continue;
                    }
                    return Err(err);
                }
                if n as usize != size_of::<uffd::UffdMsg>() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Short read from userfaultfd",
                    ));
                }

                if msg.event != userfaultfd::UFFD_EVENT_PAGEFAULT {
                    continue;
                }

                let fault_addr = msg.pf_address;
                let minor_fault = msg.pf_flags & userfaultfd::UFFD_PAGEFAULT_FLAG_MINOR != 0;

                let (range_idx, page_idx) = match fault_uffd.locate(fault_addr) {
                    Some(located) => located,
                    None => {
                        if let Some(hole) = fault_uffd.locate_hole(fault_addr) {
                            uffd::unregister(fault_uffd.fd(), hole.host_addr, hole.length)?;
                            continue;
                        }
                        return Err(io::Error::other(format!(
                            "UFFD handler: fault at {fault_addr:#x} does not belong to any registered range",
                        )));
                    }
                };
                let range = &fault_uffd.ranges()[range_idx];

                if source_failed {
                    Self::uffd_poison_page(fault_uffd.fd(), range, page_idx)?;
                    continue;
                }

                // Held until the page is installed and its served bit says
                // so, so that the snapshot writer never sees a page whose bit
                // and content disagree.
                let _serve_guard = serve_lock.lock().unwrap();

                // A missing fault on a served page is either a discard, or a
                // fault queued on another userfaultfd while the page was
                // being resolved. Only the latter leaves the page present.
                if !minor_fault
                    && served_bitmap[range_idx].is_bit_set(page_idx as usize)
                    && uffd::page_present(ranges[range_idx].page_addr(page_idx))?
                {
                    uffd::wake(fault_uffd.fd(), range.page_addr(page_idx), range.page_size)?;
                    continue;
                }

                let key = (range_idx, page_idx);

                let (served_minor, discarded) = {
                    let mut loading = pages_loading.lock().unwrap();
                    let served = served_bitmap[range_idx].is_bit_set(page_idx as usize);

                    if served && minor_fault {
                        (true, false)
                    } else if served {
                        // The page has been discarded (ie. virtio-balloon)
                        (false, true)
                    } else if !loading.insert(key) {
                        // Another worker owns this page. The thread that's
                        // handling this page will call UFFDIO_COPY or
                        // UFFDIO_CONTINUE on the page range. The kernel
                        // guarantees us that it will wake all the threads
                        // waiting on this range in the userfaultfd it
                        // resolves through. This fault may come from another
                        // one, so wake it right away: it faults again until
                        // the page is resolved.
                        uffd::wake(fault_uffd.fd(), range.page_addr(page_idx), range.page_size)?;
                        continue;
                    } else {
                        (false, false)
                    }
                };

                if served_minor {
                    // The backing page is already in the page cache. A
                    // minor fault only needs the page mapped into this VMA.
                    uffd::uffd_continue(
                        fault_uffd.fd(),
                        range.page_addr(page_idx),
                        range.page_size,
                    )
                    .or_else(|e| {
                        if e.raw_os_error() == Some(libc::EEXIST) {
                            Ok(())
                        } else {
                            Err(e)
                        }
                    })?;

                    // Do not fall through and resolve an already present page.
                    continue;
                }

                if discarded {
                    let page_addr = range.page_addr(page_idx);
                    let copy_zeroes = || {
                        uffd::copy(
                            fault_uffd.fd(),
                            page_addr,
                            zero_buf.as_ptr(),
                            range.page_size,
                        )
                    };
                    if private_zeroes {
                        // UFFDIO_ZEROPAGE would map the zero page every
                        // process shares: copy, so the page is the VM's own.
                        copy_zeroes()
                    } else {
                        match uffd::zeropage(fault_uffd.fd(), page_addr, range.page_size) {
                            // hugetlbfs does not support UFFDIO_ZEROPAGE.
                            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => copy_zeroes(),
                            result => result,
                        }
                    }
                    .or_else(|e| {
                        if e.raw_os_error() == Some(libc::EEXIST) {
                            uffd::wake(fault_uffd.fd(), page_addr, range.page_size)
                        } else {
                            Err(e)
                        }
                    })?;

                    continue;
                }

                let result = source.resolve(fault_uffd.fd(), range, page_idx);

                {
                    let mut loading = pages_loading.lock().unwrap();

                    if result.is_ok() {
                        served_bitmap[range_idx].set_bit(page_idx as usize);
                    }

                    loading.remove(&key);
                }

                if let Err(e) = result {
                    error!(
                        "UFFD handler: source error at {:#x}, poisoning unrestored guest memory: {e}",
                        range.page_addr(page_idx)
                    );
                    exit_evt.write(1).ok();
                    prefault_active = false;
                    source_failed = true;
                    Self::uffd_poison_page(fault_uffd.fd(), range, page_idx)?;
                    continue;
                }
                pages_served += 1;

                // preemptively fault that page in the guest, as it's very
                // likely it's going to access it soon, causing minor fault
                // if it's enabled.
                let is_backend_fault = idx != 0;
                if is_backend_fault && source.requires_uffd_minor_mode() {
                    uffd::uffd_continue(
                        vmm_uffd.fd(),
                        ranges[range_idx].page_addr(page_idx),
                        range.page_size,
                    )
                    .or_else(|e| {
                        if e.raw_os_error() == Some(libc::EEXIST) {
                            Ok(())
                        } else {
                            Err(e)
                        }
                    })?;
                }

                continue;
            }

            if !prefault_active {
                continue;
            }

            match Self::uffd_prefault(
                vmm_uffd.fd(),
                &mut range_idx,
                &mut page_idx,
                ranges,
                &mut source,
                &served_bitmap,
                &pages_loading,
            ) {
                Ok(0) => {
                    let mut added_uffds = uffd_registry.added_uffds.lock().unwrap();
                    uffds.append(&mut added_uffds);
                    // Every page is present, so the faults still queued on
                    // the userfaultfds only need waking up.
                    for (_, uffd) in &uffds {
                        for range in uffd.ranges() {
                            uffd::wake(uffd.fd(), range.host_addr, range.length)?;
                        }
                        for hole in uffd.holes() {
                            uffd::unregister(uffd.fd(), hole.host_addr, hole.length)?;
                        }
                    }
                    uffd_registry.done.write(1)?;

                    let elapsed = prefault_start.elapsed();
                    info!(
                        "UFFD handler: prefault done in {elapsed:.3?} — \
                         prefaulted={pages_prefaulted} served={pages_served} \
                         total={total_pages}"
                    );
                    return Ok(());
                }
                Ok(prefaulted) => pages_prefaulted += prefaulted,
                Err(e) => {
                    // Give up prefaulting but continue serving demand faults.
                    warn!("UFFD prefault: abandoning background prefault after error: {e}");
                    prefault_active = false;
                }
            }
        }
    }

    fn uffd_prefault(
        uffd_fd: BorrowedFd,
        range_idx: &mut usize,
        page_idx: &mut u64,
        ranges: &[UffdRange],
        source: &mut Box<dyn UffdMemorySource>,
        served_bitmap: &[AtomicBitmap],
        pages_loading: &Mutex<HashSet<(usize, u64)>>,
    ) -> Result<u64, io::Error> {
        let mut current_page_idx = *page_idx;
        let mut current_range_idx = *range_idx;

        'outer: loop {
            'find_range: loop {
                if current_page_idx >= ranges[current_range_idx].num_pages() {
                    if current_range_idx + 1 < ranges.len() {
                        current_range_idx += 1;
                        current_page_idx = 0;
                        continue 'find_range;
                    }

                    *range_idx = current_range_idx;
                    *page_idx = current_page_idx;
                    return Ok(0);
                }
                break 'find_range;
            }

            let range = &ranges[current_range_idx];
            let key = (current_range_idx, current_page_idx);
            let claimed = {
                let mut loading = pages_loading.lock().unwrap();

                if served_bitmap[current_range_idx].is_bit_set(current_page_idx as usize) {
                    current_page_idx += 1;
                    continue 'outer;
                }

                loading.insert(key)
            };

            if !claimed {
                // Do not advance the cursor until the page's owner publishes
                // completion or makes the page available for another attempt.
                thread::yield_now();
                continue 'outer;
            }

            let result = source.resolve(uffd_fd, range, current_page_idx);

            {
                let mut loading = pages_loading.lock().unwrap();

                if result.is_ok() {
                    served_bitmap[current_range_idx].set_bit(current_page_idx as usize);
                }

                loading.remove(&key);
            }

            match result {
                Ok(()) => {
                    current_page_idx += 1;

                    *range_idx = current_range_idx;
                    *page_idx = current_page_idx;
                    return Ok(1);
                }
                Err(e) => {
                    let page_addr = range.page_addr(current_page_idx);
                    warn!("UFFD prefault: source error at {page_addr:#x}: {e}");
                    return Err(e);
                }
            }
        }
    }

    fn validate_memory_config(
        config: &MemoryConfig,
        user_provided_zones: bool,
    ) -> Result<(u64, Vec<MemoryZoneConfig>, bool), Error> {
        let mut allow_mem_hotplug = false;

        if user_provided_zones {
            let Some(zones) = config.zones.clone() else {
                error!(
                    "User defined memory regions must be provided if the \
                    memory size is 0"
                );
                return Err(Error::MissingMemoryZones);
            };

            if zones.is_empty() {
                return Err(Error::MissingMemoryZones);
            }

            let mut total_ram_size: u64 = 0;
            for zone in zones.iter() {
                total_ram_size += zone.size;

                if zone.shared && zone.file.is_some() && zone.host_numa_node.is_some() {
                    error!(
                        "Invalid to set host NUMA policy for a memory zone \
                        backed by a regular file and mapped as 'shared'"
                    );
                    return Err(Error::InvalidSharedMemoryZoneWithHostNuma);
                }

                if zone.hotplug_size.is_some() && config.hotplug_method == HotplugMethod::Acpi {
                    error!("Invalid to set ACPI hotplug method for memory zones");
                    return Err(Error::InvalidHotplugMethodWithMemoryZones);
                }

                if let Some(hotplugged_size) = zone.hotplugged_size {
                    if let Some(hotplug_size) = zone.hotplug_size {
                        if hotplugged_size > hotplug_size {
                            error!(
                                "'hotplugged_size' {hotplugged_size} can't be bigger than \
                                'hotplug_size' {hotplug_size}",
                            );
                            return Err(Error::InvalidMemoryParameters);
                        }
                    } else {
                        error!(
                            "Invalid to define 'hotplugged_size' when there is\
                            no 'hotplug_size' for a memory zone"
                        );
                        return Err(Error::InvalidMemoryParameters);
                    }
                    if config.hotplug_method == HotplugMethod::Acpi {
                        error!(
                            "Invalid to define 'hotplugged_size' with hotplug \
                            method 'acpi'"
                        );
                        return Err(Error::InvalidMemoryParameters);
                    }
                }
            }

            Ok((total_ram_size, zones, allow_mem_hotplug))
        } else {
            if config.zones.is_some() {
                error!(
                    "User defined memory regions can't be provided if the \
                    memory size is not 0"
                );
                return Err(Error::InvalidMemoryParameters);
            }

            if config.hotplug_size.is_some() {
                allow_mem_hotplug = true;
                if config.hotplug_method == HotplugMethod::Acpi {
                    warn!(
                        "ACPI memory hotplug is deprecated and will be removed in a future release. \
                         Use --memory hotplug_method=virtio-mem instead."
                    );
                }
            }

            if let Some(hotplugged_size) = config.hotplugged_size {
                if let Some(hotplug_size) = config.hotplug_size {
                    if hotplugged_size > hotplug_size {
                        error!(
                            "'hotplugged_size' {hotplugged_size} can't be bigger than \
                            'hotplug_size' {hotplug_size}",
                        );
                        return Err(Error::InvalidMemoryParameters);
                    }
                } else {
                    error!(
                        "Invalid to define 'hotplugged_size' when there is\
                        no 'hotplug_size'"
                    );
                    return Err(Error::InvalidMemoryParameters);
                }
                if config.hotplug_method == HotplugMethod::Acpi {
                    error!(
                        "Invalid to define 'hotplugged_size' with hotplug \
                        method 'acpi'"
                    );
                    return Err(Error::InvalidMemoryParameters);
                }
            }

            // Create a single zone from the global memory config. This lets
            // us reuse the codepath for user defined memory zones.
            let zones = vec![MemoryZoneConfig {
                id: String::from(DEFAULT_MEMORY_ZONE),
                size: config.size,
                file: None,
                shared: config.shared,
                hugepages: config.hugepages,
                hugepage_size: config.hugepage_size,
                host_numa_node: None,
                hotplug_size: config.hotplug_size,
                hotplugged_size: config.hotplugged_size,
                prefault: config.prefault,
                reserve: config.reserve,
                mergeable: config.mergeable,
            }];

            Ok((config.size, zones, allow_mem_hotplug))
        }
    }

    pub fn allocate_address_space(&mut self) -> Result<(), Error> {
        let mut list = Vec::new();

        for (zone_id, memory_zone) in self.memory_zones.iter() {
            let mut regions: Vec<(Arc<GuestRegion>, bool)> = memory_zone
                .regions()
                .iter()
                .map(|r| (Arc::clone(r), false))
                .collect();

            if let Some(virtio_mem_zone) = memory_zone.virtio_mem_zone() {
                regions.push((Arc::clone(virtio_mem_zone.region()), true));
            }

            list.push((zone_id.clone(), regions));
        }

        for (zone_id, regions) in list {
            for (region, virtio_mem) in regions {
                region.register().map_err(Error::RegisterGuestRegion)?;
                let slot = region.slot().unwrap();

                let file_offset = if let Some(file_offset) = region.file_offset() {
                    file_offset.start()
                } else {
                    0
                };

                self.guest_ram_mappings.push(GuestRamMapping {
                    gpa: region.start_addr().raw_value(),
                    size: region.len(),
                    slot,
                    zone_id: zone_id.clone(),
                    virtio_mem,
                    file_offset,
                });
                self.ram_allocator
                    .allocate(Some(region.start_addr()), region.len(), None)
                    .ok_or(Error::MemoryRangeAllocation)?;
            }
        }

        // Allocate SubRegion and Reserved address ranges.
        for region in self.arch_mem_regions.iter() {
            if region.r_type == RegionType::Ram {
                // Ignore the RAM type since ranges have already been allocated
                // based on the GuestMemoryBackend regions.
                continue;
            }
            // The allocator stops at the device area, so claim only the part
            // of an entry that falls inside it.
            let last = cmp::min(
                region.base + region.size as u64 - 1,
                self.ram_allocator.end().raw_value(),
            );
            if region.base > last {
                continue;
            }
            self.ram_allocator
                .allocate(
                    Some(GuestAddress(region.base)),
                    last - region.base + 1,
                    None,
                )
                .ok_or(Error::MemoryRangeAllocation)?;
        }

        Ok(())
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    pub fn add_uefi_flash(&mut self) -> Result<(), Error> {
        // The UEFI binary requires a flash device at address 0.
        // 4 MiB memory is mapped to simulate the flash.
        let uefi_region = GuestRegion::from_mmap(
            MmapRegion::new(layout::UEFI_SIZE as usize).unwrap(),
            layout::UEFI_START,
            Arc::clone(&self.vm),
            Arc::clone(self.memory_slot_allocator()),
            false,
            false,
            false,
            hypervisor::MemoryVisibility::Private,
        )
        .map_err(Error::CreateUefiFlash)?;
        uefi_region.register().map_err(Error::CreateUefiFlash)?;
        let uefi_flash =
            GuestMemoryAtomic::new(GuestMemory::from_regions(vec![uefi_region]).unwrap());

        self.uefi_flash = Some(uefi_flash);

        Ok(())
    }

    pub fn new(
        vm: Arc<dyn hypervisor::Vm>,
        config: &MemoryConfig,
        prefault: Option<bool>,
        phys_bits: u8,
        #[cfg(feature = "sev_snp")] sev_snp_enabled: bool,
        restore_data: Option<&MemoryManagerSnapshotData>,
        existing_memory_files: HashMap<u32, File>,
    ) -> Result<Arc<Mutex<MemoryManager>>, Error> {
        trace_scoped!("MemoryManager::new");

        let user_provided_zones = config.size == 0;

        let mmio_address_space_size = mmio_address_space_size(phys_bits);
        debug_assert_eq!(
            (((mmio_address_space_size) >> 16) << 16),
            mmio_address_space_size
        );
        let start_of_platform_device_area =
            GuestAddress(mmio_address_space_size - PLATFORM_DEVICE_AREA_SIZE);
        let end_of_device_area = start_of_platform_device_area.unchecked_sub(1);

        let (ram_size, zones, allow_mem_hotplug) =
            Self::validate_memory_config(config, user_provided_zones)?;

        let next_memory_slot = Arc::new(AtomicU32::new(
            restore_data.map_or(0, |data| data.next_memory_slot),
        ));
        let memory_slot_allocator = Arc::new(MemorySlotAllocator::new(
            Arc::clone(&next_memory_slot),
            Arc::new(Mutex::new(Vec::new())),
        ));
        #[cfg(not(feature = "sev_snp"))]
        let dynamic = true;
        #[cfg(feature = "sev_snp")]
        let dynamic = !sev_snp_enabled;

        let (
            start_of_device_area,
            boot_ram,
            current_ram,
            arch_mem_regions,
            memory_zones,
            guest_memory,
            boot_guest_memory,
            hotplug_slots,
            selected_slot,
            next_hotplug_slot,
        ) = if let Some(data) = restore_data {
            let (regions, memory_zones) = Self::restore_memory_regions_and_zones(
                &data.guest_ram_mappings,
                &zones,
                existing_memory_files,
                config.thp,
                &vm,
                &memory_slot_allocator,
                dynamic,
            )?;
            let guest_memory =
                GuestMemory::from_arc_regions(regions).map_err(Error::GuestRegionCollection)?;
            let boot_guest_memory = guest_memory.clone();
            (
                GuestAddress(data.start_of_device_area),
                data.boot_ram,
                data.current_ram,
                data.arch_mem_regions.clone(),
                memory_zones,
                guest_memory,
                boot_guest_memory,
                data.hotplug_slots.clone(),
                data.selected_slot,
                data.next_hotplug_slot,
            )
        } else {
            // Init guest memory
            let arch_mem_regions = arch::arch_memory_regions();

            let ram_regions: Vec<(GuestAddress, usize)> = arch_mem_regions
                .iter()
                .filter(|r| r.2 == RegionType::Ram)
                .map(|r| (r.0, r.1))
                .collect();

            let arch_mem_regions: Vec<ArchMemRegion> = arch_mem_regions
                .iter()
                .map(|(a, b, c)| ArchMemRegion {
                    base: a.0,
                    size: *b,
                    r_type: *c,
                })
                .collect();

            let (mem_regions, mut memory_zones) = Self::create_memory_regions_from_zones(
                &ram_regions,
                &zones,
                config.thp,
                &vm,
                &memory_slot_allocator,
                dynamic,
            )?;

            let mut guest_memory =
                GuestMemory::from_arc_regions(mem_regions).map_err(Error::GuestRegionCollection)?;

            let boot_guest_memory = guest_memory.clone();

            let mut start_of_device_area =
                MemoryManager::start_addr(guest_memory.last_addr(), allow_mem_hotplug)?;

            // Update list of memory zones for resize.
            for zone in zones.iter() {
                if let Some(memory_zone) = memory_zones.get_mut(&zone.id) {
                    if let Some(hotplug_size) = zone.hotplug_size {
                        if hotplug_size == 0 {
                            error!("'hotplug_size' can't be 0");
                            return Err(Error::InvalidHotplugSize);
                        }

                        if !user_provided_zones && config.hotplug_method == HotplugMethod::Acpi {
                            let hotplug_address_space_size = hotplug_size
                                .checked_add(HOTPLUG_RAM_GAP_SIZE * (HOTPLUG_COUNT as u64 - 1))
                                .ok_or(Error::GuestAddressOverFlow)?;
                            let span = size_clear_of_reserved(
                                &arch_mem_regions,
                                start_of_device_area.0,
                                hotplug_address_space_size,
                            )?;
                            start_of_device_area = start_of_device_area
                                .checked_add(span)
                                .ok_or(Error::GuestAddressOverFlow)?;
                        } else {
                            // Alignment must be "natural" i.e. same as size of block
                            let align = virtio_devices::VIRTIO_MEM_ALIGN_SIZE;
                            let start_addr = start_of_device_area.0.div_ceil(align) * align;
                            // One contiguous region, so it goes wholly above a
                            // reserved range it would cross.
                            let start_addr =
                                base_clear_of_reserved(&arch_mem_regions, start_addr, hotplug_size);
                            let start_addr = GuestAddress(start_addr.div_ceil(align) * align);

                            let region = MemoryManager::create_ram_region(
                                &None,
                                0,
                                start_addr,
                                hotplug_size as usize,
                                zone.reserve.unwrap_or(zone.hugepages),
                                zone.shared,
                                zone.hugepages,
                                zone.hugepage_size,
                                zone.host_numa_node,
                                None,
                                config.thp,
                                Arc::clone(&vm),
                                Arc::clone(&memory_slot_allocator),
                                zone.mergeable,
                                dynamic,
                                hypervisor::MemoryVisibility::Private,
                            )?;

                            guest_memory = guest_memory
                                .insert_region(Arc::clone(&region))
                                .map_err(Error::GuestRegionCollection)?;

                            let hotplugged_size = zone.hotplugged_size.unwrap_or(0);
                            let region_size = region.len();
                            memory_zone.virtio_mem_zone = Some(VirtioMemZone {
                                region,
                                virtio_device: None,
                                hotplugged_size,
                                hugepages: zone.hugepages,
                                blocks_state: Arc::new(Mutex::new(BlocksState::new(region_size))),
                            });

                            start_of_device_area = start_addr
                                .checked_add(hotplug_size)
                                .ok_or(Error::GuestAddressOverFlow)?;
                        }
                    }
                } else {
                    return Err(Error::MissingZoneIdentifier);
                }
            }

            let mut hotplug_slots = Vec::with_capacity(HOTPLUG_COUNT);
            hotplug_slots.resize_with(HOTPLUG_COUNT, HotPlugState::default);

            (
                start_of_device_area,
                ram_size,
                ram_size,
                arch_mem_regions,
                memory_zones,
                guest_memory,
                boot_guest_memory,
                hotplug_slots,
                0,
                0,
            )
        };

        prefault::prefault_regions(&Self::prefault_regions_from_zones(
            &zones,
            &memory_zones,
            prefault,
        )?)?;

        let guest_memory = GuestMemoryAtomic::new(guest_memory);

        let allocator = Arc::new(Mutex::new(
            SystemAllocator::new(
                GuestAddress(0),
                1 << 16,
                start_of_platform_device_area,
                PLATFORM_DEVICE_AREA_SIZE,
                #[cfg(target_arch = "x86_64")]
                &[GsiApic::new(
                    X86_64_IRQ_BASE,
                    ioapic::NUM_IOAPIC_PINS as u32 - X86_64_IRQ_BASE,
                )],
                #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
                arch::IRQ_BASE,
            )
            .ok_or(Error::CreateSystemAllocator)?,
        ));

        let acpi_address = if dynamic
            && config.hotplug_method == HotplugMethod::Acpi
            && (config.hotplug_size.unwrap_or_default() > 0)
        {
            Some(
                allocator
                    .lock()
                    .unwrap()
                    .allocate_platform_mmio_addresses(None, MEMORY_MANAGER_ACPI_SIZE as u64, None)
                    .ok_or(Error::AllocateMmioAddress)?,
            )
        } else {
            None
        };

        // The start of device area and RAM area are placed next to each other.
        let end_of_ram_area = start_of_device_area.unchecked_sub(1);
        let ram_allocator = AddressAllocator::new(GuestAddress(0), start_of_device_area.0).unwrap();

        #[allow(unused_mut)]
        let mut memory_manager = MemoryManager {
            boot_guest_memory,
            guest_memory,
            next_memory_slot,
            memory_slot_allocator,
            start_of_device_area,
            end_of_device_area,
            end_of_ram_area,
            vm,
            hotplug_slots,
            selected_slot,
            mergeable: config.mergeable,
            allocator,
            hotplug_method: config.hotplug_method,
            boot_ram,
            current_ram,
            hotplug_size: config.hotplug_size.unwrap_or_default(),
            next_hotplug_slot,
            shared: config.shared,
            hugepages: config.hugepages,
            hugepage_size: config.hugepage_size,
            prefault: config.prefault,
            reserve: config.reserve,
            user_provided_zones,
            snapshot_memory_ranges: MemoryRangeTable::default(),
            cow_source: None,
            memory_zones,
            guest_ram_mappings: Vec::new(),
            uffd_handler: None,
            acpi_address,
            log_dirty: dynamic, // Cannot log dirty pages on a CVM
            arch_mem_regions,
            ram_allocator,
            dynamic,
            #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
            uefi_flash: None,
            thp: config.thp,
        };

        Ok(Arc::new(Mutex::new(memory_manager)))
    }

    #[expect(clippy::too_many_arguments)]
    pub fn new_from_snapshot(
        snapshot: &Snapshot,
        vm: Arc<dyn hypervisor::Vm>,
        config: &MemoryConfig,
        source_url: Option<&str>,
        prefault: bool,
        memory_restore_mode: MemoryRestoreMode,
        phys_bits: u8,
        exit_evt: &EventFd,
        #[cfg(feature = "sev_snp")] sev_snp_enabled: bool,
    ) -> Result<Arc<Mutex<MemoryManager>>, Error> {
        if let Some(source_url) = source_url {
            let mut memory_file_path = url_to_path(source_url).map_err(Error::Restore)?;
            memory_file_path.push(String::from(SNAPSHOT_FILENAME));

            let mem_snapshot: MemoryManagerSnapshotData =
                snapshot.to_state().map_err(Error::Restore)?;

            let mm = MemoryManager::new(
                vm,
                config,
                Some(prefault),
                phys_bits,
                #[cfg(feature = "sev_snp")]
                sev_snp_enabled,
                Some(&mem_snapshot),
                Default::default(),
            )?;

            if !mem_snapshot.memory_ranges.is_empty() {
                let memory_restore_mode = effective_restore_mode(
                    memory_restore_mode,
                    &mm.lock().unwrap().memory_zones,
                    &mem_snapshot.memory_ranges,
                );
                match memory_restore_mode {
                    MemoryRestoreMode::OnDemand
                    | MemoryRestoreMode::OnDemandNoBackgroundFetchPages
                    | MemoryRestoreMode::CopyOnAccess => {
                        let background_fetch_pages =
                            memory_restore_mode == MemoryRestoreMode::OnDemand;
                        mm.lock().unwrap().restore_by_uffd(
                            &memory_file_path,
                            &mem_snapshot.memory_ranges,
                            background_fetch_pages,
                            exit_evt,
                            memory_restore_mode == MemoryRestoreMode::CopyOnAccess,
                        )?;
                    }
                    MemoryRestoreMode::CopyOnWrite => mm
                        .lock()
                        .unwrap()
                        .mmap_cow_saved_regions(memory_file_path, &mem_snapshot.memory_ranges)?,
                    MemoryRestoreMode::Copy => mm
                        .lock()
                        .unwrap()
                        .fill_saved_regions(memory_file_path, &mem_snapshot.memory_ranges)?,
                }
            }

            Ok(mm)
        } else {
            Err(Error::RestoreMissingSourceUrl)
        }
    }

    fn memfd_create(name: &ffi::CStr, flags: u32) -> Result<RawFd, io::Error> {
        // SAFETY: FFI call with correct arguments
        let res = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };

        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res as RawFd)
        }
    }

    fn mbind(
        addr: *mut u8,
        len: u64,
        mode: u32,
        nodemask: &[u64],
        maxnode: u64,
        flags: u32,
    ) -> Result<(), io::Error> {
        // SAFETY: FFI call with correct arguments
        let res = unsafe {
            libc::syscall(
                libc::SYS_mbind,
                addr.cast::<libc::c_void>(),
                len,
                mode,
                nodemask.as_ptr(),
                maxnode,
                flags,
            )
        };

        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn create_anonymous_file(
        size: usize,
        hugepages: bool,
        hugepage_size: Option<u64>,
    ) -> Result<FileOffset, Error> {
        let fd = Self::memfd_create(
            c"ch_ram",
            libc::MFD_CLOEXEC
                | libc::MFD_ALLOW_SEALING
                | if hugepages {
                    libc::MFD_HUGETLB
                        | if let Some(hugepage_size) = hugepage_size {
                            /*
                             * From the Linux kernel:
                             * Several system calls take a flag to request "hugetlb" huge pages.
                             * Without further specification, these system calls will use the
                             * system's default huge page size.  If a system supports multiple
                             * huge page sizes, the desired huge page size can be specified in
                             * bits [26:31] of the flag arguments.  The value in these 6 bits
                             * will encode the log2 of the huge page size.
                             */

                            hugepage_size.trailing_zeros() << 26
                        } else {
                            // Use the system default huge page size
                            0
                        }
                } else {
                    0
                },
        )
        .map_err(Error::SharedFileCreate)?;

        // SAFETY: fd is valid
        let f = unsafe { File::from_raw_fd(fd) };
        f.set_len(size as u64).map_err(Error::SharedFileSetLen)?;

        // Seal the FD to prevent truncate changing the size (and triggering
        // SIGBUS in the VMM) as it may be shared with an external process.
        //
        // SAFETY: `f` provides a valid file descriptor, and `F_ADD_SEALS` takes
        // no pointer arguments.
        let res = unsafe {
            libc::fcntl(
                f.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL,
            )
        };
        if res < 0 {
            return Err(Error::SharedFileSeal(io::Error::last_os_error()));
        }

        Ok(FileOffset::new(f, 0))
    }

    fn open_backing_file(
        backing_file: &PathBuf,
        file_offset: u64,
        shared: bool,
    ) -> Result<FileOffset, Error> {
        if backing_file.is_dir() {
            Err(Error::DirectoryAsBackingFileForMemory)
        } else {
            let f = OpenOptions::new()
                .read(true)
                .write(shared)
                .open(backing_file)
                .map_err(Error::SharedFileCreate)?;

            Ok(FileOffset::new(f, file_offset))
        }
    }

    #[expect(clippy::too_many_arguments)]
    pub fn create_ram_region_raw(
        backing_file: &Option<PathBuf>,
        file_offset: u64,
        size: usize,
        reserve: bool,
        shared: bool,
        hugepages: bool,
        hugepage_size: Option<u64>,
        host_numa_node: Option<u32>,
        existing_memory_file: Option<File>,
        thp: bool,
    ) -> Result<MmapRegion<AtomicBitmap>, Error> {
        let mut mmap_flags = if reserve { 0 } else { libc::MAP_NORESERVE };

        // The duplication of mmap_flags ORing here is unfortunate but it also makes
        // the complexity of the handling clear.
        let fo = if let Some(f) = existing_memory_file {
            // It must be MAP_SHARED as we wouldn't already have an FD
            mmap_flags |= libc::MAP_SHARED;
            Some(FileOffset::new(f, file_offset))
        } else if let Some(backing_file) = backing_file {
            if shared {
                mmap_flags |= libc::MAP_SHARED;
            } else {
                mmap_flags |= libc::MAP_PRIVATE;
            }
            Some(Self::open_backing_file(backing_file, file_offset, shared)?)
        } else if shared || hugepages {
            // For hugepages we must also MAP_SHARED otherwise we will trigger #4805
            // because the MAP_PRIVATE will trigger CoW against the backing file with
            // the VFIO pinning
            mmap_flags |= libc::MAP_SHARED;
            Some(Self::create_anonymous_file(size, hugepages, hugepage_size)?)
        } else {
            mmap_flags |= libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
            None
        };

        let region = MmapRegion::build(fo, size, libc::PROT_READ | libc::PROT_WRITE, mmap_flags)
            .map_err(Error::GuestMemoryRegion)?;

        // Apply NUMA policy if needed.
        if let Some(node) = host_numa_node {
            let addr = region.as_ptr();
            let len = region.size() as u64;
            let mode = MPOL_BIND;
            let mut nodemask: Vec<u64> = Vec::new();
            let flags = MPOL_MF_STRICT | MPOL_MF_MOVE;

            // Linux is kind of buggy in the way it interprets maxnode as it
            // will cut off the last node. That's why we have to add 1 to what
            // we would consider as the proper maxnode value.
            let maxnode = node as u64 + 1 + 1;

            // Allocate the right size for the vector.
            nodemask.resize((node as usize / 64) + 1, 0);

            // Fill the global bitmask through the nodemask vector.
            let idx = (node / 64) as usize;
            let shift = node % 64;
            nodemask[idx] |= 1u64 << shift;

            // Policies are enforced by using MPOL_MF_MOVE flag as it will
            // force the kernel to move all pages that might have been already
            // allocated to the proper set of NUMA nodes. MPOL_MF_STRICT is
            // used to throw an error if MPOL_MF_MOVE didn't succeed.
            // MPOL_BIND is the selected mode as it specifies a strict policy
            // that restricts memory allocation to the nodes specified in the
            // nodemask.
            Self::mbind(addr, len, mode, &nodemask, maxnode, flags)
                .map_err(Error::ApplyNumaPolicy)?;
        }

        if thp && !hugepages {
            // SAFETY: FFI call with correct arguments
            let ret = unsafe { libc::madvise(region.as_ptr().cast(), size, libc::MADV_HUGEPAGE) };
            if ret != 0 {
                let e = io::Error::last_os_error();
                warn!("Failed to mark pages as THP eligible: {e}");
            } else {
                debug!("Successfully marked pages as THP eligible");
            }
        }

        info!(
            "RAM region mapping at 0x{:x} (size = 0x{:x})",
            region.as_ptr() as u64,
            size
        );

        Ok(region)
    }

    #[expect(clippy::too_many_arguments)]
    pub fn create_ram_region(
        backing_file: &Option<PathBuf>,
        file_offset: u64,
        start_addr: GuestAddress,
        size: usize,
        reserve: bool,
        shared: bool,
        hugepages: bool,
        hugepage_size: Option<u64>,
        host_numa_node: Option<u32>,
        existing_memory_file: Option<File>,
        thp: bool,
        vm: Arc<dyn hypervisor::Vm>,
        slot_allocator: Arc<MemorySlotAllocator>,
        mergeable: bool,
        log_dirty: bool,
        visibility: hypervisor::MemoryVisibility,
    ) -> Result<Arc<GuestRegion>, Error> {
        let r = Self::create_ram_region_raw(
            backing_file,
            file_offset,
            size,
            reserve,
            shared,
            hugepages,
            hugepage_size,
            host_numa_node,
            existing_memory_file,
            thp,
        )?;

        let region = GuestRegion::from_mmap(
            r,
            start_addr,
            vm,
            slot_allocator,
            mergeable,
            false,
            log_dirty,
            visibility,
        )
        .map_err(Error::RegisterGuestRegion)?;
        Ok(Arc::new(region))
    }

    // Duplicate of `memory_zone_get_align_size` that does not require a `zone`
    fn get_prefault_align_size(
        backing_file: &Option<PathBuf>,
        hugepages: bool,
        hugepage_size: Option<u64>,
    ) -> Result<u64, Error> {
        let page_size = get_page_size();
        match (hugepages, hugepage_size, backing_file) {
            (false, _, _) => Ok(page_size),
            (true, Some(hugepage_size), _) => Ok(hugepage_size),
            (true, None, _) => {
                // There are two scenarios here:
                //  - `hugepages` is enabled but `hugepage_size` is not specified:
                //     Call `statfs` for `/dev/hugepages` for getting the default size of hugepage
                //  - The backing file is specified:
                //     Call `statfs` for the file and get its `f_bsize`.  If the value is larger than the page
                //     size of normal page, just use the `f_bsize` because the file is in a hugetlbfs.  If the
                //     value is less than or equal to the page size, just use the page size.
                let path = backing_file
                    .as_ref()
                    .map_or(Ok("/dev/hugepages"), |pathbuf| {
                        pathbuf.to_str().ok_or(Error::InvalidMemoryParameters)
                    })?;
                let align_size = cmp::max(page_size, statfs_get_bsize(path)?);
                Ok(align_size)
            }
        }
    }

    // Update the GuestMemory with the new range
    fn add_region(&mut self, region: Arc<GuestRegion>) -> Result<(), Error> {
        let guest_memory = self
            .guest_memory
            .memory()
            .insert_region(region)
            .map_err(Error::GuestRegionCollection)?;
        self.guest_memory.lock().unwrap().replace(guest_memory);

        Ok(())
    }

    //
    // Calculate the start address of an area next to RAM.
    //
    // If memory hotplug is allowed, the start address needs to be aligned
    // (rounded-up) to 128MiB boundary and separated from the previous RAM
    // region by a 256MiB gap. This prevents the guest from accessing memory
    // across two separate mappings with a single access.
    // If memory hotplug is not allowed, there is no alignment required.
    // And it must also start at the 64bit start.
    fn start_addr(mem_end: GuestAddress, allow_mem_hotplug: bool) -> Result<GuestAddress, Error> {
        let mut start_addr = if allow_mem_hotplug {
            GuestAddress(mem_end.0 | (HOTPLUG_RAM_ALIGN_SIZE - 1))
        } else {
            mem_end
        };

        start_addr = start_addr
            .checked_add(1)
            .ok_or(Error::GuestAddressOverFlow)?;

        #[cfg(not(target_arch = "riscv64"))]
        if mem_end < layout::MEM_32BIT_RESERVED_START {
            return Ok(layout::RAM_64BIT_START);
        }

        if allow_mem_hotplug {
            start_addr = start_addr
                .checked_add(HOTPLUG_RAM_GAP_SIZE)
                .ok_or(Error::GuestAddressOverFlow)?;
        }

        Ok(start_addr)
    }

    pub fn add_ram_region(
        &mut self,
        start_addr: GuestAddress,
        size: usize,
    ) -> Result<Arc<GuestRegion>, Error> {
        // Allocate memory for the region
        let region = MemoryManager::create_ram_region(
            &None,
            0,
            start_addr,
            size,
            self.reserve.unwrap_or(self.hugepages),
            self.shared,
            self.hugepages,
            self.hugepage_size,
            None,
            None,
            self.thp,
            Arc::clone(&self.vm),
            Arc::clone(self.memory_slot_allocator()),
            self.memory_zones
                .get(DEFAULT_MEMORY_ZONE)
                .map_or(self.mergeable, |z| z.mergeable),
            self.log_dirty,
            hypervisor::MemoryVisibility::Private,
        )?;

        if self.prefault {
            let page_size =
                Self::get_prefault_align_size(&None, self.hugepages, self.hugepage_size)? as usize;
            prefault::prefault_regions(&[prefault::PrefaultRegion {
                addr: region.as_ptr() as usize,
                size,
                page_size,
                host_numa_node: None,
            }])?;
        }

        region.register().map_err(Error::RegisterGuestRegion)?;
        let slot = region.slot().unwrap();
        self.add_region(Arc::clone(&region))?;

        self.guest_ram_mappings.push(GuestRamMapping {
            gpa: region.start_addr().raw_value(),
            size: region.len(),
            slot,
            zone_id: DEFAULT_MEMORY_ZONE.to_string(),
            virtio_mem: false,
            file_offset: 0,
        });

        Ok(region)
    }

    fn hotplug_ram_region(&mut self, size: usize) -> Result<Arc<GuestRegion>, Error> {
        info!("Hotplugging new RAM: {size}");

        // Check that there is a free slot
        if self.next_hotplug_slot >= HOTPLUG_COUNT {
            return Err(Error::NoSlotAvailable);
        }

        // "Inserted" DIMM must have a size that is a multiple of 128MiB
        if !size.is_multiple_of(HOTPLUG_RAM_ALIGN_SIZE as usize) {
            return Err(Error::InvalidSize);
        }

        let total_hotplug_ram = self
            .hotplug_slots
            .iter()
            .filter(|slot| slot.active)
            .map(|slot| slot.length)
            .sum::<u64>()
            + size as u64;
        if total_hotplug_ram > self.hotplug_size {
            return Err(Error::InsufficientHotplugRam(
                total_hotplug_ram,
                self.hotplug_size,
            ));
        }

        let start_addr = MemoryManager::start_addr(self.guest_memory.memory().last_addr(), true)?;
        let start_addr = GuestAddress(base_clear_of_reserved(
            &self.arch_mem_regions,
            start_addr.0,
            size as u64,
        ));

        if start_addr
            .checked_add((size - 1).try_into().unwrap())
            .unwrap()
            > self.end_of_ram_area
        {
            return Err(Error::InsufficientHotplugRam(
                total_hotplug_ram,
                self.hotplug_size,
            ));
        }

        let region = self.add_ram_region(start_addr, size)?;

        // Add region to the list of regions associated with the default
        // memory zone.
        if let Some(memory_zone) = self.memory_zones.get_mut(DEFAULT_MEMORY_ZONE) {
            memory_zone.regions.push(Arc::clone(&region));
        }

        // Tell the allocator
        self.ram_allocator
            .allocate(Some(start_addr), size as GuestUsize, None)
            .ok_or(Error::MemoryRangeAllocation)?;

        // Update the slot so that it can be queried via the I/O port
        let slot = &mut self.hotplug_slots[self.next_hotplug_slot];
        slot.active = true;
        slot.inserting = true;
        slot.base = region.start_addr().0;
        slot.length = region.len();

        self.next_hotplug_slot += 1;

        Ok(region)
    }

    pub fn guest_memory(&self) -> GuestMemoryAtomic<GuestMemory> {
        self.guest_memory.clone()
    }

    pub fn boot_guest_memory(&self) -> GuestMemory {
        self.boot_guest_memory.clone()
    }

    pub fn allocator(&self) -> Arc<Mutex<SystemAllocator>> {
        Arc::clone(&self.allocator)
    }

    pub fn reserved_regions(&self) -> Vec<(u64, u64)> {
        reserved_spans(&self.arch_mem_regions)
    }

    pub fn start_of_device_area(&self) -> GuestAddress {
        self.start_of_device_area
    }

    pub fn end_of_device_area(&self) -> GuestAddress {
        self.end_of_device_area
    }

    pub fn memory_slot_allocator(&self) -> &Arc<MemorySlotAllocator> {
        &self.memory_slot_allocator
    }

    pub fn virtio_mem_resize(&mut self, id: &str, size: u64) -> Result<(), Error> {
        if let Some(memory_zone) = self.memory_zones.get_mut(id) {
            if let Some(virtio_mem_zone) = &mut memory_zone.virtio_mem_zone {
                if let Some(virtio_mem_device) = virtio_mem_zone.virtio_device.as_ref() {
                    virtio_mem_device
                        .lock()
                        .unwrap()
                        .resize(size)
                        .map_err(Error::VirtioMemResizeFail)?;
                }

                // Keep the hotplugged_size up to date.
                virtio_mem_zone.hotplugged_size = size;
            } else {
                error!("Failed resizing virtio-mem region: No virtio-mem handler");
                return Err(Error::MissingVirtioMemHandler);
            }

            return Ok(());
        }

        error!("Failed resizing virtio-mem region: Unknown memory zone");
        Err(Error::UnknownMemoryZone)
    }

    /// In case this function resulted in adding a new memory region to the
    /// guest memory, the new region is returned to the caller. The virtio-mem
    /// use case never adds a new region as the whole hotpluggable memory has
    /// already been allocated at boot time.
    pub fn resize(&mut self, desired_ram: u64) -> Result<Option<Arc<GuestRegion>>, Error> {
        if self.user_provided_zones {
            error!(
                "Not allowed to resize guest memory when backed with user \
                defined memory zones."
            );
            return Err(Error::InvalidResizeWithMemoryZones);
        }

        let mut region: Option<Arc<GuestRegion>> = None;
        match self.hotplug_method {
            HotplugMethod::VirtioMem => {
                if desired_ram < self.boot_ram {
                    return Err(Error::InvalidResizeBelowBootSize(
                        desired_ram,
                        self.boot_ram,
                    ));
                }

                if !self.dynamic {
                    return Ok(region);
                }

                self.virtio_mem_resize(DEFAULT_MEMORY_ZONE, desired_ram - self.boot_ram)?;
                self.current_ram = desired_ram;
            }
            HotplugMethod::Acpi => {
                if desired_ram > self.current_ram {
                    if !self.dynamic {
                        return Ok(region);
                    }

                    region =
                        Some(self.hotplug_ram_region((desired_ram - self.current_ram) as usize)?);
                    self.current_ram = desired_ram;
                }
            }
        }
        Ok(region)
    }

    pub fn resize_zone(&mut self, zone: &MemoryZoneConfig, desired_ram: u64) -> Result<(), Error> {
        if !self.user_provided_zones {
            error!(
                "Not allowed to resize guest memory zone when no zone is \
                defined."
            );
            return Err(Error::ResizeZone);
        }

        if desired_ram < zone.size {
            return Err(Error::InvalidResizeBelowBootSize(desired_ram, zone.size));
        }

        self.virtio_mem_resize(&zone.id, desired_ram - zone.size)
    }

    pub fn is_hardlink(f: &File) -> bool {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: FFI call with correct arguments
        let ret = unsafe { libc::fstat(f.as_raw_fd(), stat.as_mut_ptr()) };
        if ret != 0 {
            error!("Couldn't fstat the backing file");
            return false;
        }

        // SAFETY: stat is valid
        unsafe { (*stat.as_ptr()).st_nlink as usize > 0 }
    }

    pub fn virtio_mem_plugged_size(&self) -> u64 {
        self.memory_zones
            .values()
            .filter_map(|zone| {
                zone.virtio_mem_zone
                    .as_ref()?
                    .virtio_device
                    .as_ref()
                    .map(|dev| dev.lock().unwrap().plugged_size())
            })
            .sum()
    }

    pub fn memory_zones(&self) -> &MemoryZones {
        &self.memory_zones
    }

    pub fn memory_zones_mut(&mut self) -> &mut MemoryZones {
        &mut self.memory_zones
    }

    pub fn memory_range_table(
        &self,
        mode: MemoryRangePolicy,
    ) -> result::Result<MemoryRangeTable, MigratableError> {
        let mut table = MemoryRangeTable::default();

        for memory_zone in self.memory_zones.values() {
            if let Some(virtio_mem_zone) = memory_zone.virtio_mem_zone() {
                table.extend(virtio_mem_zone.plugged_ranges());
            }

            for region in memory_zone.regions() {
                let gpa = region.start_addr().raw_value();
                let len = region.len();

                let shared_file_offset = region
                    .file_offset()
                    .filter(|_| region.flags() & libc::MAP_SHARED == libc::MAP_SHARED);

                match mode {
                    MemoryRangePolicy::Full => {}
                    MemoryRangePolicy::SkipPersisted => {
                        // Content already persisted through the backing file.
                        if let Some(file_offset) = shared_file_offset
                            && Self::is_hardlink(file_offset.file())
                        {
                            continue;
                        }
                    }
                    MemoryRangePolicy::Sparse => {
                        if let Some(file_offset) = shared_file_offset
                            && let Some(ranges) = Self::sparse_extents(file_offset, gpa, len)
                        {
                            for range in ranges {
                                table.push(range);
                            }
                            continue;
                        }
                    }
                }

                table.push(MemoryRange { gpa, length: len });
            }
        }

        // Memory zones iterate in hash order.
        table.sort();
        Ok(table)
    }

    /// Return the populated extents of a memory range, or `None` if the
    /// caller should fall back onto sending the entire region.
    fn sparse_extents(file_offset: &FileOffset, gpa: u64, len: u64) -> Option<Vec<MemoryRange>> {
        let offset = file_offset.start();
        let end = offset + len;
        let mut cursor = offset;
        let mut ranges = Vec::new();
        loop {
            match next_data_extent(file_offset.file().as_fd(), cursor, end) {
                Ok(Some((data_offset, ext_len))) => {
                    let range_gpa = data_offset
                        .checked_sub(offset)
                        .and_then(|delta| gpa.checked_add(delta))?;
                    ranges.push(MemoryRange {
                        gpa: range_gpa,
                        length: ext_len,
                    });
                    cursor = data_offset + ext_len;
                }
                Ok(None) => break,
                Err(_) => return None,
            }
        }
        Some(ranges)
    }

    pub fn snapshot_data(&self) -> MemoryManagerSnapshotData {
        MemoryManagerSnapshotData {
            memory_ranges: self.snapshot_memory_ranges.clone(),
            guest_ram_mappings: self.guest_ram_mappings.clone(),
            start_of_device_area: self.start_of_device_area.0,
            boot_ram: self.boot_ram,
            current_ram: self.current_ram,
            arch_mem_regions: self.arch_mem_regions.clone(),
            hotplug_slots: self.hotplug_slots.clone(),
            next_memory_slot: self.next_memory_slot.load(Ordering::SeqCst),
            selected_slot: self.selected_slot,
            next_hotplug_slot: self.next_hotplug_slot,
        }
    }

    /// Restore the final ACPI state after migration has populated guest memory.
    pub(crate) fn restore_state(&mut self, snapshot: &Snapshot) -> Result<(), MigratableError> {
        let state: MemoryManagerSnapshotData = snapshot.to_state()?;
        self.hotplug_slots = state.hotplug_slots;
        self.selected_slot = state.selected_slot;
        self.next_hotplug_slot = state.next_hotplug_slot;
        Ok(())
    }

    pub fn memory_slot_fds(&self) -> HashMap<u32, RawFd> {
        let mut memory_slot_fds = HashMap::new();
        for guest_ram_mapping in &self.guest_ram_mappings {
            let slot = guest_ram_mapping.slot;
            let guest_memory = self.guest_memory.memory();
            let file = guest_memory
                .find_region(GuestAddress(guest_ram_mapping.gpa))
                .unwrap()
                .file_offset()
                .unwrap()
                .file();
            memory_slot_fds.insert(slot, file.as_raw_fd());
        }
        memory_slot_fds
    }

    pub fn acpi_address(&self) -> Option<GuestAddress> {
        self.acpi_address
    }

    pub fn num_guest_ram_mappings(&self) -> u32 {
        self.guest_ram_mappings.len() as u32
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    pub fn uefi_flash(&self) -> GuestMemoryAtomic<GuestMemory> {
        self.uefi_flash.as_ref().unwrap().clone()
    }

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    pub fn coredump_memory_regions(&self, mem_offset: u64) -> CoredumpMemoryRegions {
        let mut mapping_sorted_by_gpa = self.guest_ram_mappings.clone();
        mapping_sorted_by_gpa.sort_by_key(|m| m.gpa);

        let mut mem_offset_in_elf = mem_offset;
        let mut ram_maps = BTreeMap::new();
        for mapping in mapping_sorted_by_gpa.iter() {
            ram_maps.insert(
                mapping.gpa,
                CoredumpMemoryRegion {
                    mem_offset_in_elf,
                    mem_size: mapping.size,
                },
            );
            mem_offset_in_elf += mapping.size;
        }

        CoredumpMemoryRegions { ram_maps }
    }

    #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
    pub fn coredump_iterate_save_mem(
        &mut self,
        dump_state: &DumpState,
    ) -> result::Result<(), GuestDebuggableError> {
        let snapshot_memory_ranges = self
            .memory_range_table(MemoryRangePolicy::Full)
            .map_err(|e| GuestDebuggableError::Coredump(e.into()))?;

        if snapshot_memory_ranges.is_empty() {
            return Ok(());
        }

        let coredump_file = dump_state.file.as_ref().unwrap();

        let guest_memory = self.guest_memory.memory();
        let mut total_bytes: u64 = 0;

        for range in snapshot_memory_ranges.ranges() {
            let mut offset: u64 = 0;
            loop {
                let bytes_written = guest_memory
                    .write_volatile_to(
                        GuestAddress(range.gpa + offset),
                        &mut coredump_file.as_fd(),
                        (range.length - offset) as usize,
                    )
                    .map_err(|e| GuestDebuggableError::Coredump(e.into()))?;
                offset += bytes_written as u64;
                total_bytes += bytes_written as u64;

                if offset == range.length {
                    break;
                }
            }
        }

        debug!("coredump total bytes {total_bytes}");
        Ok(())
    }
}

struct MemoryNotify {
    slot_id: usize,
}

impl Aml for MemoryNotify {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        let object = aml::Path::new(&format!("M{:03}", self.slot_id));
        aml::If::new(
            &aml::Equal::new(&aml::Arg(0), &self.slot_id),
            vec![&aml::Notify::new(&object, &aml::Arg(1))],
        )
        .to_aml_bytes(sink);
    }
}

struct MemorySlot {
    slot_id: usize,
}

impl Aml for MemorySlot {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        aml::Device::new(
            format!("M{:03}", self.slot_id).as_str().into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0C80")),
                &aml::Name::new("_UID".into(), &self.slot_id),
                /*
                _STA return value:
                Bit [0] – Set if the device is present.
                Bit [1] – Set if the device is enabled and decoding its resources.
                Bit [2] – Set if the device should be shown in the UI.
                Bit [3] – Set if the device is functioning properly (cleared if device failed its diagnostics).
                Bit [4] – Set if the battery is present.
                Bits [31:5] – Reserved (must be cleared).
                */
                &aml::Method::new(
                    "_STA".into(),
                    0,
                    false,
                    // Call into MSTA method which will interrogate device
                    vec![&aml::Return::new(&aml::MethodCall::new(
                        "MSTA".into(),
                        vec![&self.slot_id],
                    ))],
                ),
                // Get details of memory
                &aml::Method::new(
                    "_CRS".into(),
                    0,
                    false,
                    // Call into MCRS which provides actual memory details
                    vec![&aml::Return::new(&aml::MethodCall::new(
                        "MCRS".into(),
                        vec![&self.slot_id],
                    ))],
                ),
            ],
        )
        .to_aml_bytes(sink);
    }
}

struct MemorySlots {
    slots: usize,
}

impl Aml for MemorySlots {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        for slot_id in 0..self.slots {
            MemorySlot { slot_id }.to_aml_bytes(sink);
        }
    }
}

struct MemoryMethods {
    slots: usize,
}

impl Aml for MemoryMethods {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        // Add "MTFY" notification method
        let mut memory_notifies = Vec::new();
        for slot_id in 0..self.slots {
            memory_notifies.push(MemoryNotify { slot_id });
        }

        let mut memory_notifies_refs: Vec<&dyn Aml> = Vec::new();
        for memory_notifier in memory_notifies.iter() {
            memory_notifies_refs.push(memory_notifier);
        }

        aml::Method::new("MTFY".into(), 2, true, memory_notifies_refs).to_aml_bytes(sink);

        // MSCN method
        aml::Method::new(
            "MSCN".into(),
            0,
            true,
            vec![
                // Take lock defined above
                &aml::Acquire::new("MLCK".into(), 0xffff),
                &aml::Store::new(&aml::Local(0), &aml::ZERO),
                &aml::While::new(
                    &aml::LessThan::new(&aml::Local(0), &self.slots),
                    vec![
                        // Write slot number (in first argument) to I/O port via field
                        &aml::Store::new(&aml::Path::new("\\_SB_.MHPC.MSEL"), &aml::Local(0)),
                        // Check if MINS bit is set (inserting)
                        &aml::If::new(
                            &aml::Equal::new(&aml::Path::new("\\_SB_.MHPC.MINS"), &aml::ONE),
                            // Notify device if it is
                            vec![
                                &aml::MethodCall::new(
                                    "MTFY".into(),
                                    vec![&aml::Local(0), &aml::ONE],
                                ),
                                // Reset MINS bit
                                &aml::Store::new(&aml::Path::new("\\_SB_.MHPC.MINS"), &aml::ONE),
                            ],
                        ),
                        // Check if MRMV bit is set
                        &aml::If::new(
                            &aml::Equal::new(&aml::Path::new("\\_SB_.MHPC.MRMV"), &aml::ONE),
                            // Notify device if it is (with the eject constant 0x3)
                            vec![
                                &aml::MethodCall::new("MTFY".into(), vec![&aml::Local(0), &3u8]),
                                // Reset MRMV bit
                                &aml::Store::new(&aml::Path::new("\\_SB_.MHPC.MRMV"), &aml::ONE),
                            ],
                        ),
                        &aml::Add::new(&aml::Local(0), &aml::Local(0), &aml::ONE),
                    ],
                ),
                // Release lock
                &aml::Release::new("MLCK".into()),
            ],
        )
        .to_aml_bytes(sink);

        // Memory status method
        aml::Method::new(
            "MSTA".into(),
            1,
            true,
            vec![
                // Take lock defined above
                &aml::Acquire::new("MLCK".into(), 0xffff),
                // Write slot number (in first argument) to I/O port via field
                &aml::Store::new(&aml::Path::new("\\_SB_.MHPC.MSEL"), &aml::Arg(0)),
                &aml::Store::new(&aml::Local(0), &aml::ZERO),
                // Check if MEN_ bit is set, if so make the local variable 0xf (see _STA for details of meaning)
                &aml::If::new(
                    &aml::Equal::new(&aml::Path::new("\\_SB_.MHPC.MEN_"), &aml::ONE),
                    vec![&aml::Store::new(&aml::Local(0), &0xfu8)],
                ),
                // Release lock
                &aml::Release::new("MLCK".into()),
                // Return 0 or 0xf
                &aml::Return::new(&aml::Local(0)),
            ],
        )
        .to_aml_bytes(sink);

        // Memory range method
        aml::Method::new(
            "MCRS".into(),
            1,
            true,
            vec![
                // Take lock defined above
                &aml::Acquire::new("MLCK".into(), 0xffff),
                // Write slot number (in first argument) to I/O port via field
                &aml::Store::new(&aml::Path::new("\\_SB_.MHPC.MSEL"), &aml::Arg(0)),
                &aml::Name::new(
                    "MR64".into(),
                    &aml::ResourceTemplate::new(vec![&aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::Cacheable,
                        true,
                        0x0000_0000_0000_0000u64,
                        0xFFFF_FFFF_FFFF_FFFEu64,
                        None,
                    )]),
                ),
                &aml::CreateQWordField::new(
                    &aml::Path::new("MINL"),
                    &aml::Path::new("MR64"),
                    &14usize,
                ),
                &aml::CreateDWordField::new(
                    &aml::Path::new("MINH"),
                    &aml::Path::new("MR64"),
                    &18usize,
                ),
                &aml::CreateQWordField::new(
                    &aml::Path::new("MAXL"),
                    &aml::Path::new("MR64"),
                    &22usize,
                ),
                &aml::CreateDWordField::new(
                    &aml::Path::new("MAXH"),
                    &aml::Path::new("MR64"),
                    &26usize,
                ),
                &aml::CreateQWordField::new(
                    &aml::Path::new("LENL"),
                    &aml::Path::new("MR64"),
                    &38usize,
                ),
                &aml::CreateDWordField::new(
                    &aml::Path::new("LENH"),
                    &aml::Path::new("MR64"),
                    &42usize,
                ),
                &aml::Store::new(&aml::Path::new("MINL"), &aml::Path::new("\\_SB_.MHPC.MHBL")),
                &aml::Store::new(&aml::Path::new("MINH"), &aml::Path::new("\\_SB_.MHPC.MHBH")),
                &aml::Store::new(&aml::Path::new("LENL"), &aml::Path::new("\\_SB_.MHPC.MHLL")),
                &aml::Store::new(&aml::Path::new("LENH"), &aml::Path::new("\\_SB_.MHPC.MHLH")),
                &aml::Add::new(
                    &aml::Path::new("MAXL"),
                    &aml::Path::new("MINL"),
                    &aml::Path::new("LENL"),
                ),
                &aml::Add::new(
                    &aml::Path::new("MAXH"),
                    &aml::Path::new("MINH"),
                    &aml::Path::new("LENH"),
                ),
                &aml::If::new(
                    &aml::LessThan::new(&aml::Path::new("MAXL"), &aml::Path::new("MINL")),
                    vec![&aml::Add::new(
                        &aml::Path::new("MAXH"),
                        &aml::ONE,
                        &aml::Path::new("MAXH"),
                    )],
                ),
                &aml::Subtract::new(&aml::Path::new("MAXL"), &aml::Path::new("MAXL"), &aml::ONE),
                // Release lock
                &aml::Release::new("MLCK".into()),
                &aml::Return::new(&aml::Path::new("MR64")),
            ],
        )
        .to_aml_bytes(sink);
    }
}

impl Aml for MemoryManager {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        if let Some(acpi_address) = self.acpi_address {
            // Memory Hotplug Controller
            aml::Device::new(
                "_SB_.MHPC".into(),
                vec![
                    &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A06")),
                    &aml::Name::new("_UID".into(), &"Memory Hotplug Controller"),
                    // Mutex to protect concurrent access as we write to choose slot and then read back status
                    &aml::Mutex::new("MLCK".into(), 0),
                    &aml::Name::new(
                        "_CRS".into(),
                        &aml::ResourceTemplate::new(vec![&aml::AddressSpace::new_memory(
                            aml::AddressSpaceCacheable::NotCacheable,
                            true,
                            acpi_address.0,
                            acpi_address.0 + MEMORY_MANAGER_ACPI_SIZE as u64 - 1,
                            None,
                        )]),
                    ),
                    // OpRegion and Fields map MMIO range into individual field values
                    &aml::OpRegion::new(
                        "MHPR".into(),
                        aml::OpRegionSpace::SystemMemory,
                        &(acpi_address.0 as usize),
                        &MEMORY_MANAGER_ACPI_SIZE,
                    ),
                    &aml::Field::new(
                        "MHPR".into(),
                        aml::FieldAccessType::DWord,
                        aml::FieldLockRule::NoLock,
                        aml::FieldUpdateRule::Preserve,
                        vec![
                            aml::FieldEntry::Named(*b"MHBL", 32), // Base (low 4 bytes)
                            aml::FieldEntry::Named(*b"MHBH", 32), // Base (high 4 bytes)
                            aml::FieldEntry::Named(*b"MHLL", 32), // Length (low 4 bytes)
                            aml::FieldEntry::Named(*b"MHLH", 32), // Length (high 4 bytes)
                        ],
                    ),
                    &aml::Field::new(
                        "MHPR".into(),
                        aml::FieldAccessType::DWord,
                        aml::FieldLockRule::NoLock,
                        aml::FieldUpdateRule::Preserve,
                        vec![
                            aml::FieldEntry::Reserved(128),
                            aml::FieldEntry::Named(*b"MHPX", 32), // PXM
                        ],
                    ),
                    &aml::Field::new(
                        "MHPR".into(),
                        aml::FieldAccessType::Byte,
                        aml::FieldLockRule::NoLock,
                        aml::FieldUpdateRule::WriteAsZeroes,
                        vec![
                            aml::FieldEntry::Reserved(160),
                            aml::FieldEntry::Named(*b"MEN_", 1), // Enabled
                            aml::FieldEntry::Named(*b"MINS", 1), // Inserting
                            aml::FieldEntry::Named(*b"MRMV", 1), // Removing
                            aml::FieldEntry::Named(*b"MEJ0", 1), // Ejecting
                        ],
                    ),
                    &aml::Field::new(
                        "MHPR".into(),
                        aml::FieldAccessType::DWord,
                        aml::FieldLockRule::NoLock,
                        aml::FieldUpdateRule::Preserve,
                        vec![
                            aml::FieldEntry::Named(*b"MSEL", 32), // Selector
                            aml::FieldEntry::Named(*b"MOEV", 32), // Event
                            aml::FieldEntry::Named(*b"MOSC", 32), // OSC
                        ],
                    ),
                    &MemoryMethods {
                        slots: self.hotplug_slots.len(),
                    },
                    &MemorySlots {
                        slots: self.hotplug_slots.len(),
                    },
                ],
            )
            .to_aml_bytes(sink);
        } else {
            aml::Device::new(
                "_SB_.MHPC".into(),
                vec![
                    &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A06")),
                    &aml::Name::new("_UID".into(), &"Memory Hotplug Controller"),
                    // Empty MSCN for GED
                    &aml::Method::new("MSCN".into(), 0, true, vec![]),
                ],
            )
            .to_aml_bytes(sink);
        }

        // The 32 bit PCI window holds no reserved ranges, but the 64 bit one can
        // span one, so only the ranges above 4 GiB need declaring.
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let reserved: Vec<_> = self
                .arch_mem_regions
                .iter()
                .filter(|r| {
                    r.r_type == RegionType::Reserved
                        && r.base >= layout::RAM_64BIT_START.raw_value()
                })
                .map(|r| {
                    aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::NotCacheable,
                        true,
                        r.base,
                        r.base + r.size as u64 - 1,
                        None,
                    )
                })
                .collect();

            if !reserved.is_empty() {
                let crs: Vec<&dyn Aml> = reserved.iter().map(|r| r as &dyn Aml).collect();
                aml::Device::new(
                    "_SB_.MRSV".into(),
                    vec![
                        &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0C02")),
                        &aml::Name::new("_UID".into(), &"Reserved Memory"),
                        &aml::Name::new("_CRS".into(), &aml::ResourceTemplate::new(crs)),
                    ],
                )
                .to_aml_bytes(sink);
            }
        }
    }
}

impl Pausable for MemoryManager {}

impl Drop for MemoryManager {
    fn drop(&mut self) {
        self.stop_uffd_handler();
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MemoryManagerSnapshotData {
    memory_ranges: MemoryRangeTable,
    guest_ram_mappings: Vec<GuestRamMapping>,
    start_of_device_area: u64,
    boot_ram: u64,
    current_ram: u64,
    arch_mem_regions: Vec<ArchMemRegion>,
    hotplug_slots: Vec<HotPlugState>,
    next_memory_slot: u32,
    selected_slot: usize,
    next_hotplug_slot: usize,
}

impl Snapshottable for MemoryManager {
    fn id(&self) -> String {
        MEMORY_MANAGER_SNAPSHOT_ID.to_string()
    }

    fn snapshot(&mut self) -> result::Result<Snapshot, MigratableError> {
        let memory_ranges = self.memory_range_table(MemoryRangePolicy::SkipPersisted)?;

        // Store locally this list of ranges as it will be used through the
        // Transportable::send() implementation. The point is to avoid the
        // duplication of code regarding the creation of the path for each
        // region. The 'snapshot' step creates the list of memory regions,
        // including information about the need to copy a memory region or
        // not. This saves the 'send' step having to go through the same
        // process, and instead it can directly proceed with storing the
        // memory range content for the ranges requiring it.
        self.snapshot_memory_ranges = memory_ranges;

        Ok(Snapshot::from_data(SnapshotData::new_from_state(
            &self.snapshot_data(),
        )?))
    }
}

impl Transportable for MemoryManager {
    fn send(
        &self,
        _snapshot: &Snapshot,
        destination_url: &str,
    ) -> result::Result<(), MigratableError> {
        if self.snapshot_memory_ranges.is_empty() {
            return Ok(());
        }

        let mut memory_file_path = url_to_path(destination_url)?;
        memory_file_path.push(String::from(SNAPSHOT_FILENAME));

        let mut memory_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&memory_file_path)
            .with_context(|| format!("Error creating memory snapshot file {memory_file_path:?}"))
            .map_err(MigratableError::MigrateSend)?;

        let total_len: u64 = self
            .snapshot_memory_ranges
            .ranges()
            .iter()
            .map(|r| r.length)
            .sum();

        let guest_memory = self.guest_memory.memory();

        if let Some(source) = &self.cow_source
            && source.ranges == self.snapshot_memory_ranges
        {
            match clone_file_range(&source.file, &memory_file, total_len) {
                Ok(()) => return write_private_pages(&guest_memory, source, &mut memory_file),
                Err(e) => {
                    warn!("Snapshot: restore source not cloned, writing all guest memory: {e}");
                }
            }
        }

        // Pre-size the file so per-region write_at lands at the dense-layout
        // offset. On filesystems that support sparse files unwritten bytes
        // become real holes; on others the kernel zero-fills the allocation,
        // which is still byte-correct. If extending the file is not
        // supported by the destination filesystem (some FUSE backends
        // reject ftruncate-extend with EOPNOTSUPP), fall back to the dense
        // write path which never writes past the growing EOF.
        let sparse_layout = memory_file.set_len(total_len).is_ok();

        let copy_on_access = self
            .uffd_handler
            .as_ref()
            .and_then(|h| h.copy_on_access.as_ref());
        let mut file_cursor: u64 = 0;

        for range in self.snapshot_memory_ranges.ranges() {
            if let Some(pages) = copy_on_access {
                save_copy_on_access_range(
                    &guest_memory,
                    pages,
                    range,
                    &mut memory_file,
                    file_cursor,
                    sparse_layout,
                )?;
            } else {
                save_guest_range(
                    &guest_memory,
                    range.gpa,
                    range.length,
                    &mut memory_file,
                    file_cursor,
                    sparse_layout,
                )?;
            }

            file_cursor += range.length;
        }

        debug_assert_eq!(file_cursor, total_len);
        Ok(())
    }
}

/// Save `len` bytes of guest memory at `gpa` to `memory_file` at
/// `file_cursor`, reading a shared file-backed region's backing file and
/// anything else through the guest mapping.
fn save_guest_range(
    guest_memory: &GuestMemory,
    gpa: u64,
    len: u64,
    memory_file: &mut File,
    file_cursor: u64,
    sparse_layout: bool,
) -> result::Result<(), MigratableError> {
    let mut wrote_sparse = false;
    if sparse_layout
        && let Some(region) = guest_memory.find_region(GuestAddress(gpa))
        && (region.flags() & libc::MAP_SHARED) == libc::MAP_SHARED
        && let Some(file_offset) = region.file_offset()
    {
        let region_base = region.start_addr().raw_value();
        let in_fd_off = file_offset.start()
            + gpa
                .checked_sub(region_base)
                .expect("range outside its region");
        wrote_sparse =
            write_region_sparse(file_offset.file(), in_fd_off, memory_file, file_cursor, len)
                .context("Error writing sparse memory snapshot region")
                .map_err(MigratableError::MigrateSend)?;
    }

    if !wrote_sparse {
        // Dense fallback: anonymous mmap or hugetlbfs (no
        // SEEK_HOLE).
        write_guest_range(guest_memory, memory_file, file_cursor, gpa, len)?;
    }
    Ok(())
}

/// Save `range` of a copy-on-access VM's memory to `memory_file` at
/// `file_cursor`. A page the guest never accessed is copied from the restore
/// source, not read through the guest mapping, where reading it would copy
/// it into the VM. A shared region's backing file only holds the pages that
/// were served, so it cannot be read on its own either.
fn save_copy_on_access_range(
    guest_memory: &GuestMemory,
    pages: &CopyOnAccessPages,
    range: &MemoryRange,
    memory_file: &mut File,
    file_cursor: u64,
    sparse_layout: bool,
) -> result::Result<(), MigratableError> {
    // The segments are found by host address, so the range must be in one
    // mapping.
    guest_memory
        .find_region(GuestAddress(range.gpa))
        .filter(|region| range.gpa + range.length <= region.start_addr().raw_value() + region.len())
        .ok_or_else(|| {
            MigratableError::MigrateSend(anyhow!(
                "Memory range {:#x}+{:#x} is not inside one guest memory region",
                range.gpa,
                range.length
            ))
        })?;
    let host_addr = guest_memory
        .get_host_address(GuestAddress(range.gpa))
        .map_err(|e| MigratableError::MigrateSend(anyhow!(e)))? as u64;

    // A part is copied from the source with `serve_lock` held, so that the
    // handler cannot install any of it meanwhile. Guest memory is read with
    // it released: reading a discarded page faults, and the handler needs
    // the lock to resolve that fault.
    let page_present = |addr: u64| uffd::page_present(addr).unwrap_or(true);
    let mut done: u64 = 0;
    while done < range.length {
        let serve_guard = pages.serve_lock.lock().unwrap();
        let segment = pages.next_segment(host_addr + done, range.length - done, &page_present);
        let segment_end = segment.end();
        match segment {
            CopyOnAccessSegment::Source {
                offset,
                len,
                source_offset,
            } => {
                let dst_offset = file_cursor + done + offset;
                if sparse_layout {
                    copy_region(&pages.source, source_offset, memory_file, dst_offset, len)
                } else {
                    copy_region_dense(&pages.source, source_offset, memory_file, dst_offset, len)
                }
                .context("Error copying unaccessed memory from the restore source")
                .map_err(MigratableError::MigrateSend)?;
                drop(serve_guard);
            }
            CopyOnAccessSegment::Guest { offset, len } => {
                // Served or present. A page discarded since faults back in
                // as zeroes, which is what a discarded page holds.
                drop(serve_guard);
                save_guest_range(
                    guest_memory,
                    range.gpa + done + offset,
                    len,
                    memory_file,
                    file_cursor + done + offset,
                    sparse_layout,
                )?;
            }
        }
        done += segment_end;
    }
    Ok(())
}

impl Migratable for MemoryManager {
    // Start the dirty log in the hypervisor (kvm/mshv).
    // Also, reset the dirty bitmap logged by the vmm.
    // Just before we do a bulk copy we want to start/clear the dirty log so that
    // pages touched during our bulk copy are tracked.
    fn start_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        self.vm
            .start_dirty_log()
            .context("Error starting VM dirty log")
            .map_err(MigratableError::MigrateSend)?;

        for r in self.guest_memory.memory().iter() {
            (**r).bitmap().reset();
        }

        Ok(())
    }

    fn stop_dirty_log(&mut self) -> result::Result<(), MigratableError> {
        self.vm
            .stop_dirty_log()
            .context("Error stopping VM dirty log")
            .map_err(MigratableError::MigrateSend)?;

        Ok(())
    }

    // Generate a table for the pages that are dirty. The dirty pages are collapsed
    // together in the table if they are contiguous.
    fn dirty_log(&mut self) -> result::Result<MemoryRangeTable, MigratableError> {
        let page_size = get_page_size();
        let mut table = MemoryRangeTable::default();
        for r in &self.guest_ram_mappings {
            let vm_dirty_bitmap = self
                .vm
                .get_dirty_log(r.slot, r.gpa, r.size)
                .context("Error getting VM dirty log")
                .map_err(MigratableError::MigrateSend)?;
            let vmm_dirty_bitmap = match self.guest_memory.memory().find_region(GuestAddress(r.gpa))
            {
                Some(region) => {
                    assert_eq!(region.start_addr().raw_value(), r.gpa);
                    assert_eq!(region.len(), r.size);
                    (**region).bitmap().get_and_reset()
                }
                None => {
                    return Err(MigratableError::MigrateSend(anyhow!(
                        "Error finding 'guest memory region' with address {:x}",
                        r.gpa
                    )));
                }
            };

            let dirty_bitmap = vm_dirty_bitmap
                .iter()
                .zip(vmm_dirty_bitmap.iter())
                .map(|(x, y)| x | y);

            let ranges_before = table.ranges().len();
            table.extend_from_dirty_bitmap(dirty_bitmap, r.gpa, page_size);
            let slot_ranges = &table.ranges()[ranges_before..];

            trace!(
                "Dirty memory range table for slot {}: ranges = {} size = {} KiB",
                r.slot,
                slot_ranges.len(),
                slot_ranges.iter().map(|r| r.length).sum::<u64>() / 1024,
            );
        }
        Ok(table)
    }
}

// Streams guest memory `[gpa, gpa + length)` into `file` at `file_offset`.
fn write_guest_range(
    guest_memory: &GuestMemory,
    file: &mut File,
    file_offset: u64,
    gpa: u64,
    length: u64,
) -> result::Result<(), MigratableError> {
    file.seek(SeekFrom::Start(file_offset))
        .context("Error seeking memory snapshot file")
        .map_err(MigratableError::MigrateSend)?;
    let mut offset: u64 = 0;
    // Manual partial-write loop preserves the workaround for
    // https://github.com/rust-vmm/vm-memory/issues/174
    while offset < length {
        let bytes_written = guest_memory
            .write_volatile_to(GuestAddress(gpa + offset), file, (length - offset) as usize)
            .context("Error writing memory snapshot region")
            .map_err(MigratableError::MigrateSend)?;
        offset += bytes_written as u64;
    }
    Ok(())
}

// Writes the guest pages that no longer read from the restore source over
// the clone of that source in `file`.
fn write_private_pages(
    guest_memory: &GuestMemory,
    source: &CowSource,
    file: &mut File,
) -> result::Result<(), MigratableError> {
    let mut file_offset: u64 = 0;
    for range in source.ranges.ranges() {
        let host_addr = guest_memory
            .get_host_address(GuestAddress(range.gpa))
            .context("Error locating guest memory range")
            .map_err(MigratableError::MigrateSend)?;
        let private_ranges = source
            .pagemap
            .private_ranges(host_addr as u64, range.length)
            .context("Error reading the pagemap")
            .map_err(MigratableError::MigrateSend)?;
        for private in private_ranges {
            write_guest_range(
                guest_memory,
                file,
                file_offset + private.start,
                range.gpa + private.start,
                private.end - private.start,
            )?;
        }
        file_offset += range.length;
    }
    Ok(())
}

// Fails when `file` ends before the saved ranges do. The ranges sit back to
// back in the file, so they end at the sum of their lengths.
fn check_snapshot_file_covers_ranges(
    file: &File,
    saved_regions: &MemoryRangeTable,
) -> Result<(), Error> {
    let ranges_end = saved_regions
        .ranges()
        .iter()
        .try_fold(0u64, |end, r| end.checked_add(r.length))
        .ok_or_else(|| {
            Error::SnapshotRead(io::Error::new(
                io::ErrorKind::InvalidData,
                "saved memory ranges overflow a file offset",
            ))
        })?;
    let file_len = file.metadata().map_err(Error::SnapshotOpen)?.len();
    if file_len < ranges_end {
        return Err(Error::SnapshotRead(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "snapshot memory file is {file_len} bytes, shorter than the saved ranges' {ranges_end}"
            ),
        )));
    }
    Ok(())
}

// Reports whether every saved range is page-aligned and lies wholly inside a
// single plain private-anonymous guest region — the MAP_FIXED overlay
// preconditions — and no two overlap. File-backed regions are rejected:
// their stale mapping metadata would misdirect a later snapshot or fd
// consumer. Overlapping ranges, which only a malformed snapshot has, are
// rejected because every range is mapped before any hole is remapped, so a
// hole of one range remapped anonymous would read zero over the data
// another range mapped there.
fn is_restore_cow_compatible(guest_memory: &GuestMemory, saved_regions: &MemoryRangeTable) -> bool {
    let page_size = get_page_size();
    let mut file_offset: u64 = 0;
    for range in saved_regions.ranges() {
        if !file_offset.is_multiple_of(page_size)
            || !range.gpa.is_multiple_of(page_size)
            || !range.length.is_multiple_of(page_size)
        {
            return false;
        }
        let Some(end) = range.gpa.checked_add(range.length) else {
            return false;
        };
        let ok = guest_memory
            .find_region(GuestAddress(range.gpa))
            .is_some_and(|r| {
                r.file_offset().is_none() && end <= r.start_addr().raw_value() + r.len()
            });
        if !ok {
            return false;
        }
        let Some(next) = file_offset.checked_add(range.length) else {
            return false;
        };
        file_offset = next;
    }
    !saved_ranges_overlap_each_other(saved_regions)
}

// Whether two saved ranges share a guest address. Empty ranges share none.
fn saved_ranges_overlap_each_other(saved_regions: &MemoryRangeTable) -> bool {
    let mut spans: Vec<(u64, u64)> = saved_regions
        .ranges()
        .iter()
        .filter(|r| r.length > 0)
        .map(|r| (r.gpa, r.gpa.saturating_add(r.length)))
        .collect();
    spans.sort_unstable();
    spans.windows(2).any(|w| w[1].0 < w[0].1)
}

// Whether any saved range lies in a zone's virtio-mem region. A requested
// size of 0 does not prove the guest finished unplugging, and a private file
// map under a virtio-mem block would make unplug's MADV_DONTNEED revert to
// snapshot content instead of zeroing it.
fn saved_ranges_in_virtio_mem(
    memory_zones: &MemoryZones,
    saved_regions: &MemoryRangeTable,
) -> bool {
    let windows: Vec<(u64, u64)> = memory_zones
        .values()
        .filter_map(|z| z.virtio_mem_zone.as_ref())
        .map(|v| (v.region.start_addr().raw_value(), v.region.len()))
        .collect();
    saved_ranges_overlap(saved_regions, &windows)
}

// The mode a restore in `mode` uses. Copy-on-access falls back to the eager
// copy when a saved range lies in a virtio-mem region, for the reason
// copy-on-write does: a block discarded before it is touched again would
// read back the snapshot's content instead of zeroes, as the handler does
// not see a discard of a page that is not in memory.
fn effective_restore_mode(
    mode: MemoryRestoreMode,
    memory_zones: &MemoryZones,
    saved_regions: &MemoryRangeTable,
) -> MemoryRestoreMode {
    if mode == MemoryRestoreMode::CopyOnAccess
        && saved_ranges_in_virtio_mem(memory_zones, saved_regions)
    {
        info!("Restore (mode=copyonaccess): plugged virtio-mem blocks, falling back to copy");
        return MemoryRestoreMode::Copy;
    }
    mode
}

// Whether any saved range overlaps one of the `(start, len)` GPA windows.
fn saved_ranges_overlap(saved_regions: &MemoryRangeTable, windows: &[(u64, u64)]) -> bool {
    saved_regions.ranges().iter().any(|r| {
        let end = r.gpa.saturating_add(r.length);
        windows
            .iter()
            .any(|&(start, len)| r.gpa < start.saturating_add(len) && start < end)
    })
}

// Maps each saved range over its guest RAM window, re-applying the owning
// region's reserve policy and the THP policy. Ranges must have passed
// `is_restore_cow_compatible`.
fn do_mmap_cow_saved_regions(
    guest_memory: &GuestMemory,
    memory_file: &File,
    saved_regions: &MemoryRangeTable,
    thp: bool,
) -> Result<(), Error> {
    do_mmap_cow_saved_regions_with(
        guest_memory,
        memory_file,
        saved_regions,
        thp,
        HoleRemapLimits::default(),
    )
    .map(|_| ())
}

// As `do_mmap_cow_saved_regions`, with the hole remap limits given. Returns
// the hole remap report of each saved range.
fn do_mmap_cow_saved_regions_with(
    guest_memory: &GuestMemory,
    memory_file: &File,
    saved_regions: &MemoryRangeTable,
    thp: bool,
    limits: HoleRemapLimits,
) -> Result<Vec<HoleRemapReport>, Error> {
    let mut file_offset: u64 = 0;
    let mut mappings = Vec::with_capacity(saved_regions.ranges().len());
    for range in saved_regions.ranges() {
        // Zones map with their own reserve setting, so take MAP_NORESERVE
        // from the region actually backing this range rather than from the
        // global memory config.
        let reserve_flag = guest_memory
            .find_region(GuestAddress(range.gpa))
            .map(|region| region.flags() & libc::MAP_NORESERVE)
            .ok_or_else(|| {
                Error::SnapshotMmap(io::Error::other("saved range outside guest memory"))
            })?;
        let host_addr = guest_memory
            .get_host_address(GuestAddress(range.gpa))
            .map_err(|e| Error::SnapshotMmap(io::Error::other(e)))?;
        let length = range.length as usize;
        // SAFETY: the window is page-aligned, wholly inside a live private
        // anonymous region nothing consumes yet, so the MAP_FIXED replacement
        // cannot clobber foreign mappings. The fd stays valid for the call.
        let ret = unsafe {
            libc::mmap(
                host_addr.cast(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_FIXED | reserve_flag,
                memory_file.as_raw_fd(),
                file_offset as libc::off_t,
            )
        };
        if ret == libc::MAP_FAILED {
            return Err(Error::SnapshotMmap(io::Error::last_os_error()));
        }
        mappings.push(CowMapping {
            host: ret.cast(),
            len: length,
            file_offset,
            map_flags: reserve_flag,
        });
        file_offset = file_offset.checked_add(range.length).ok_or_else(|| {
            Error::SnapshotMmap(io::Error::other("snapshot range file offset overflow"))
        })?;
    }

    // Before the THP advice below, so it covers the anonymous ranges too.
    // The holes of every range compete for one budget.
    let reports = remap_cow_holes(&mappings, memory_file, limits, |addr, len, flags| {
        // SAFETY: remap_cow_holes passes ranges inside the mappings just
        // installed above, which nothing uses yet.
        unsafe { map_anon_fixed(addr, len, flags) }
    })?;

    let mut summary = HoleRemapReport::default();
    for ((range, mapping), report) in saved_regions.ranges().iter().zip(&mappings).zip(&reports) {
        debug!(
            "Restore (mode=copyonwrite): range at gpa 0x{:x} (size = 0x{:x}): {}",
            range.gpa, range.length, report,
        );
        summary.add(report);
        if thp {
            // SAFETY: host/len name the private mapping installed above.
            let adv =
                unsafe { libc::madvise(mapping.host.cast(), mapping.len, libc::MADV_HUGEPAGE) };
            if adv != 0 {
                warn!(
                    "Restore (mode=copyonwrite): MADV_HUGEPAGE failed: {}",
                    io::Error::last_os_error()
                );
            }
        }
    }
    info!(
        "Restore (mode=copyonwrite): snapshot file holes: ranges={} {}",
        saved_regions.ranges().len(),
        summary,
    );
    Ok(reports)
}

// Holes in the snapshot file shorter than this stay mapped from the file.
// Each remapped hole costs VMAs (below), and one under 64 KiB would hold
// little page cache. 64 KiB is a multiple of every page size Linux uses (4,
// 16 and 64 KiB), and holes are page-aligned before this applies. A hole
// under 2 MiB cannot hold a transparent huge page, but neither could that
// part of the file mapping, whose private copies are never collapsed.
const COW_HOLE_REMAP_MIN_SIZE: u64 = 64 << 10;
// Most holes remapped in one restore: the holes of all its saved ranges
// compete, and when there are more the largest win. Each remapped hole
// splits the file mapping around it into two more VMAs, so the remap adds at
// most 2 * 8192 VMAs, about a quarter of the default vm.max_map_count
// (65530), which the assertion below holds it to. Each saved range's own file
// mapping can add two more by splitting the guest region around it; nothing
// here bounds the number of ranges, which comes from the snapshot, but those
// VMAs exist with or without the remap. A golden image's memory file has a
// few thousand data extents, so about as many holes, which this covers twice
// over.
const COW_HOLE_REMAP_MAX_HOLES: usize = 8192;
const _: () = assert!(2 * COW_HOLE_REMAP_MAX_HOLES < 65530 / 3);

#[derive(Clone, Copy, Debug)]
struct HoleRemapLimits {
    min_size: u64,
    max_holes: usize,
}

impl Default for HoleRemapLimits {
    fn default() -> Self {
        HoleRemapLimits {
            min_size: COW_HOLE_REMAP_MIN_SIZE,
            max_holes: COW_HOLE_REMAP_MAX_HOLES,
        }
    }
}

// One saved range's private file mapping: `len` bytes at `host` of the
// snapshot file from `file_offset`, mapped with `map_flags` besides
// MAP_PRIVATE.
#[derive(Clone, Copy, Debug)]
struct CowMapping {
    host: *mut u8,
    len: usize,
    file_offset: u64,
    map_flags: libc::c_int,
}

// A hole of the snapshot file in the mapping `range`, at absolute file
// offset `off`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CowHole {
    range: usize,
    off: u64,
    len: u64,
}

// Every hole found is either remapped or counted under one of the skips:
// found == holes + skipped_small + skipped_cap + skipped_failed.
#[derive(Debug, Default, PartialEq, Eq)]
struct HoleRemapReport {
    // Data extents seen in the window.
    extents: usize,
    // Page-aligned holes found, whatever their size.
    found: usize,
    // Holes kept mapped from the file as shorter than the minimum size, as
    // over the hole budget, and as not tried or failed after an mmap failed.
    skipped_small: usize,
    skipped_cap: usize,
    skipped_failed: usize,
    // Holes, and bytes, now mapped anonymous.
    holes: usize,
    bytes: u64,
    // Why some or all holes kept the file mapping, if they did.
    fallback: Option<&'static str>,
}

impl HoleRemapReport {
    // Adds `other`'s counts to these; the first fallback seen is kept.
    fn add(&mut self, other: &HoleRemapReport) {
        self.extents += other.extents;
        self.found += other.found;
        self.skipped_small += other.skipped_small;
        self.skipped_cap += other.skipped_cap;
        self.skipped_failed += other.skipped_failed;
        self.holes += other.holes;
        self.bytes += other.bytes;
        self.fallback = self.fallback.or(other.fallback);
    }
}

impl fmt::Display for HoleRemapReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "extents={} holes_found={} holes_remapped={} bytes_remapped={} \
             skipped_small={} skipped_cap={} skipped_failed={} fallback={}",
            self.extents,
            self.found,
            self.holes,
            self.bytes,
            self.skipped_small,
            self.skipped_cap,
            self.skipped_failed,
            self.fallback.unwrap_or("none"),
        )
    }
}

// Calls `on_hole(offset, len)` for each page-aligned hole in `[start, start
// + len)` of `file`, at absolute file offsets in file order, and returns the
// number of data extents seen. Anything past EOF is a hole. Errors if
// SEEK_HOLE is unsupported or the walk fails, possibly after some calls.
fn cow_file_holes(
    file: &File,
    start: u64,
    len: u64,
    page_size: u64,
    mut on_hole: impl FnMut(u64, u64),
) -> io::Result<usize> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "range overflow"))?;
    let mut extents = 0;
    let mut push_hole = |lo: u64, hi: u64| {
        let lo = lo.next_multiple_of(page_size);
        let hi = hi - hi % page_size;
        if hi > lo {
            on_hole(lo, hi - lo);
        }
    };
    let mut cursor = start;
    while let Some((data_off, data_len)) = next_data_extent(file.as_fd(), cursor, end)? {
        extents += 1;
        push_hole(cursor, data_off);
        cursor = data_off + data_len;
    }
    push_hole(cursor, end);
    Ok(extents)
}

// The holes chosen for remapping, at most `max_holes` of them, kept as the
// holes are walked so that memory stays bounded however many there are: the
// largest, the earlier (by range, then offset) of equal sizes.
struct HoleChooser {
    max_holes: usize,
    // A min-heap on preference: the least preferred hole is on top.
    heap: BinaryHeap<Reverse<HolePreference>>,
}

// Orders holes by preference: the larger first, then the earlier range, then
// the earlier offset.
type HolePreference = (u64, Reverse<usize>, Reverse<u64>);

impl HoleChooser {
    fn new(max_holes: usize) -> Self {
        HoleChooser {
            max_holes,
            heap: BinaryHeap::new(),
        }
    }

    // Offers `hole`; returns the hole dropped over the cap, `hole` itself or
    // one kept before, if any.
    fn offer(&mut self, hole: CowHole) -> Option<CowHole> {
        self.heap
            .push(Reverse((hole.len, Reverse(hole.range), Reverse(hole.off))));
        if self.heap.len() <= self.max_holes {
            return None;
        }
        let Reverse((len, Reverse(range), Reverse(off))) = self.heap.pop()?;
        Some(CowHole { range, off, len })
    }

    // Offers every hole `other` kept; calls `on_dropped` with each hole
    // dropped over the cap, from either chooser.
    fn merge(&mut self, other: HoleChooser, mut on_dropped: impl FnMut(CowHole)) {
        for Reverse((len, Reverse(range), Reverse(off))) in other.heap {
            if let Some(dropped) = self.offer(CowHole { range, off, len }) {
                on_dropped(dropped);
            }
        }
    }

    // The holes chosen, by range then offset.
    fn into_chosen(self) -> Vec<CowHole> {
        let mut chosen: Vec<_> = self
            .heap
            .into_iter()
            .map(|Reverse((len, Reverse(range), Reverse(off)))| CowHole { range, off, len })
            .collect();
        chosen.sort_unstable_by_key(|h| (h.range, h.off));
        chosen
    }
}

// Offers `chooser` the holes of mapping `range` that `walk` passes to its
// callback, counting them in `reports`. They compete among themselves while
// the walk runs, and with the holes of other ranges only once it has
// succeeded, so a failed walk leaves `chooser` as it was; the range then
// keeps its whole file mapping.
fn offer_range_holes(
    chooser: &mut HoleChooser,
    reports: &mut [HoleRemapReport],
    range: usize,
    limits: HoleRemapLimits,
    walk: impl FnOnce(&mut dyn FnMut(u64, u64)) -> io::Result<usize>,
) {
    let mut walked = HoleChooser::new(limits.max_holes);
    let report = &mut reports[range];
    let walk = walk(&mut |off, len| {
        report.found += 1;
        if len < limits.min_size {
            report.skipped_small += 1;
        } else if walked.offer(CowHole { range, off, len }).is_some() {
            report.skipped_cap += 1;
        }
    });
    match walk {
        Ok(extents) => {
            reports[range].extents = extents;
            chooser.merge(walked, |dropped| reports[dropped.range].skipped_cap += 1);
        }
        Err(e) => {
            debug!("Restore (mode=copyonwrite): cannot walk snapshot file holes: {e}");
            reports[range] = HoleRemapReport {
                fallback: Some("seek_hole_unsupported"),
                ..Default::default()
            };
        }
    }
}

// Maps `len` bytes at `addr` private anonymous, with `map_flags` besides.
//
// # Safety
//
// `addr..addr + len` must lie in a mapping the caller owns and nothing uses:
// MAP_FIXED replaces whatever is there.
unsafe fn map_anon_fixed(addr: *mut u8, len: usize, map_flags: libc::c_int) -> io::Result<()> {
    // SAFETY: the caller vouches for the range; an anonymous mapping takes
    // no fd.
    let ret = unsafe {
        libc::mmap(
            addr.cast(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED | map_flags,
            -1,
            0,
        )
    };
    if ret == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// Replaces the holes of the private file mappings of `file` in `mappings`
// with private anonymous memory, through `map_anon` (`map_anon_fixed` but in
// tests). Both read as zeroes and keep guest writes private, but a guest
// touching a hole through the file mapping first faults a zero page into the
// file's page cache and then copies it, so a mostly-empty guest fills the
// host page cache with zeroes. The holes of all mappings compete for
// `limits`. Keeps a mapping whole when SEEK_HOLE is unsupported, and keeps
// the holes `limits` leaves out mapped from the file, as well as every hole
// left once one remap has failed. The mappings must be page-aligned and not
// yet used by anything. Returns the report of each mapping.
fn remap_cow_holes(
    mappings: &[CowMapping],
    file: &File,
    limits: HoleRemapLimits,
    map_anon: impl FnMut(*mut u8, usize, libc::c_int) -> io::Result<()>,
) -> Result<Vec<HoleRemapReport>, Error> {
    remap_cow_holes_with(mappings, file, limits, map_anon, |addr, len, flags, off| {
        // SAFETY: remap_cow_holes_with passes a hole of a mapping the caller
        // vouches for, without MAP_FIXED; the fd stays valid for the call.
        let ret = unsafe {
            libc::mmap(
                addr.cast(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                file.as_raw_fd(),
                off,
            )
        };
        if ret == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(ret.cast())
    })
}

// `remap_cow_holes`, mapping the file back after a failed remap through
// `map_file` (mmap(2) of the file with the given flags and offset, but in
// tests).
fn remap_cow_holes_with(
    mappings: &[CowMapping],
    file: &File,
    limits: HoleRemapLimits,
    mut map_anon: impl FnMut(*mut u8, usize, libc::c_int) -> io::Result<()>,
    mut map_file: impl FnMut(*mut u8, usize, libc::c_int, libc::off_t) -> io::Result<*mut u8>,
) -> Result<Vec<HoleRemapReport>, Error> {
    let page_size = get_page_size();
    let mut reports: Vec<HoleRemapReport> = mappings
        .iter()
        .map(|_| HoleRemapReport::default())
        .collect();
    // Holes too small to remap are only counted, so a sparse save with
    // millions of one-page holes costs no memory for them.
    let mut chooser = HoleChooser::new(limits.max_holes);
    for (range, m) in mappings.iter().enumerate() {
        if !m.file_offset.is_multiple_of(page_size) || !(m.host as u64).is_multiple_of(page_size) {
            reports[range].fallback = Some("unaligned");
            continue;
        }
        offer_range_holes(&mut chooser, &mut reports, range, limits, |on_hole| {
            cow_file_holes(file, m.file_offset, m.len as u64, page_size, on_hole)
        });
    }

    let mut failed = false;
    for hole in chooser.into_chosen() {
        let report = &mut reports[hole.range];
        if failed {
            report.skipped_failed += 1;
            report.fallback.get_or_insert("mmap_failed");
            continue;
        }
        let m = &mappings[hole.range];
        // SAFETY: the hole lies within [file_offset, file_offset +
        // len) of its mapping, so addr..addr + hole.len lies within
        // the mapping at m.host.
        let addr = unsafe { m.host.add((hole.off - m.file_offset) as usize) };
        let Err(e) = map_anon(addr, hole.len as usize, m.map_flags) else {
            report.holes += 1;
            report.bytes += hole.len;
            continue;
        };
        // A failed MAP_FIXED normally leaves the file mapping as it was
        // (an older kernel may instead have unmapped the whole range), so
        // map the file back only where nothing is mapped. EEXIST only says
        // some page of the range is still mapped; it is read as "the file
        // mapping survived" on the assumption that a failed MAP_FIXED
        // never leaves the range partly unmapped (it either unmapped
        // nothing, as at vm.max_map_count, or the whole range). MAP_FIXED
        // would fail here as the remap did when that ran out of VMAs
        // (ENOMEM at vm.max_map_count), since replacing part of the mapping
        // needs the same splits.
        match map_file(
            addr,
            hole.len as usize,
            libc::MAP_PRIVATE | libc::MAP_FIXED_NOREPLACE | m.map_flags,
            hole.off as libc::off_t,
        ) {
            Ok(ret) if ret != addr => {
                // A kernel before 4.17 takes MAP_FIXED_NOREPLACE as a hint
                // and maps elsewhere, which tells nothing about whether the
                // range is still mapped: drop the stray copy and fail the
                // restore rather than risk leaving the hole unmapped.
                // SAFETY: ret..ret + len is the mapping just made, which
                // nothing else knows of.
                unsafe { libc::munmap(ret.cast(), hole.len as usize) };
                return Err(Error::SnapshotMmap(io::Error::other(format!(
                    "remapping a snapshot file hole failed ({e}) and the kernel \
                     ignored MAP_FIXED_NOREPLACE when mapping the file back"
                ))));
            }
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
            Err(e) => return Err(Error::SnapshotMmap(e)),
        }
        warn!("Restore (mode=copyonwrite): remapping a snapshot file hole failed: {e}");
        report.skipped_failed += 1;
        report.fallback = Some("mmap_failed");
        failed = true;
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    #[test]
    fn guest_ram_stays_clear_of_reserved() {
        use arch::RegionType;

        use super::{ArchMemRegion, base_clear_of_reserved, size_clear_of_reserved};

        const GIB: u64 = 1 << 30;
        let regions = vec![ArchMemRegion {
            base: 1012 * GIB,
            size: (12 * GIB) as usize,
            r_type: RegionType::Reserved,
        }];

        // An ACPI window crossing the range extends its full size past it.
        assert_eq!(
            size_clear_of_reserved(&regions, 1001 * GIB, 15 * GIB).unwrap(),
            38 * GIB
        );
        assert_eq!(
            size_clear_of_reserved(&regions, 8 * GIB, 8 * GIB).unwrap(),
            8 * GIB
        );

        // Overlapping hotplugged RAM or virtio-mem regions are placed after it.
        assert_eq!(
            base_clear_of_reserved(&regions, 1008 * GIB, 8 * GIB),
            1024 * GIB
        );
        assert_eq!(
            base_clear_of_reserved(&regions, 1001 * GIB, 64 * GIB),
            1024 * GIB
        );
        assert_eq!(base_clear_of_reserved(&regions, 8 * GIB, 8 * GIB), 8 * GIB);
    }

    use std::env;
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;

    use vm_migration::protocol::{MemoryRange, MemoryRangeTable};

    use super::*;

    struct RecordingUffdMemorySource {
        attempts: Arc<Mutex<Vec<(u64, u64)>>>,
        fail_next: bool,
    }

    impl UffdMemorySource for RecordingUffdMemorySource {
        fn resolve(
            &mut self,
            _uffd_fd: BorrowedFd<'_>,
            range: &UffdRange,
            page_idx: u64,
        ) -> Result<(), io::Error> {
            self.attempts
                .lock()
                .unwrap()
                .push((range.host_addr, page_idx));

            if self.fail_next {
                self.fail_next = false;
                return Err(io::Error::other("test source failure"));
            }

            Ok(())
        }

        fn requires_uffd_minor_mode(&self) -> bool {
            false
        }
    }

    fn new_served_bitmap(ranges: &[UffdRange]) -> Vec<AtomicBitmap> {
        ranges
            .iter()
            .map(|range| {
                AtomicBitmap::new(
                    range.length as usize,
                    NonZeroUsize::new(range.page_size as usize).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn uffd_prefault_skips_present_pages_and_crosses_ranges() {
        let page = get_page_size();
        let ranges = [
            UffdRange {
                host_addr: 0x10_0000,
                length: 2 * page,
                source_offset: 0,
                page_size: page,
            },
            UffdRange {
                host_addr: 0x20_0000,
                length: page,
                source_offset: 2 * page,
                page_size: page,
            },
        ];
        let served_bitmap = new_served_bitmap(&ranges);
        served_bitmap[0].set_bit(0);
        let pages_loading = Mutex::new(HashSet::new());

        let attempts = Arc::new(Mutex::new(Vec::new()));
        let mut source: Box<dyn UffdMemorySource> = Box::new(RecordingUffdMemorySource {
            attempts: Arc::clone(&attempts),
            fail_next: false,
        });
        let uffd_file = tempfile::tempfile().unwrap();
        let mut range_idx = 0;
        let mut page_idx = 0;

        assert_eq!(
            MemoryManager::uffd_prefault(
                uffd_file.as_fd(),
                &mut range_idx,
                &mut page_idx,
                &ranges,
                &mut source,
                &served_bitmap,
                &pages_loading,
            )
            .unwrap(),
            1
        );
        assert_eq!((range_idx, page_idx), (0, 2));

        assert_eq!(
            MemoryManager::uffd_prefault(
                uffd_file.as_fd(),
                &mut range_idx,
                &mut page_idx,
                &ranges,
                &mut source,
                &served_bitmap,
                &pages_loading,
            )
            .unwrap(),
            1
        );
        assert_eq!((range_idx, page_idx), (1, 1));

        assert_eq!(
            MemoryManager::uffd_prefault(
                uffd_file.as_fd(),
                &mut range_idx,
                &mut page_idx,
                &ranges,
                &mut source,
                &served_bitmap,
                &pages_loading,
            )
            .unwrap(),
            0
        );
        assert_eq!((range_idx, page_idx), (1, 1));
        assert_eq!(
            *attempts.lock().unwrap(),
            vec![(ranges[0].host_addr, 1), (ranges[1].host_addr, 0)]
        );
    }

    #[test]
    fn uffd_prefault_retries_page_after_source_failure() {
        let page = get_page_size();
        let ranges = [UffdRange {
            host_addr: 0x10_0000,
            length: page,
            source_offset: 0,
            page_size: page,
        }];
        let served_bitmap = new_served_bitmap(&ranges);
        let pages_loading = Mutex::new(HashSet::new());
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let mut source: Box<dyn UffdMemorySource> = Box::new(RecordingUffdMemorySource {
            attempts: Arc::clone(&attempts),
            fail_next: true,
        });
        let uffd_file = tempfile::tempfile().unwrap();
        let mut range_idx = 0;
        let mut page_idx = 0;

        let error = MemoryManager::uffd_prefault(
            uffd_file.as_fd(),
            &mut range_idx,
            &mut page_idx,
            &ranges,
            &mut source,
            &served_bitmap,
            &pages_loading,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "test source failure");
        assert_eq!((range_idx, page_idx), (0, 0));
        assert!(pages_loading.lock().unwrap().is_empty());
        assert!(!served_bitmap[0].is_bit_set(0));

        assert_eq!(
            MemoryManager::uffd_prefault(
                uffd_file.as_fd(),
                &mut range_idx,
                &mut page_idx,
                &ranges,
                &mut source,
                &served_bitmap,
                &pages_loading,
            )
            .unwrap(),
            1
        );
        assert_eq!((range_idx, page_idx), (0, 1));
        assert!(pages_loading.lock().unwrap().is_empty());
        assert!(served_bitmap[0].is_bit_set(0));
        assert_eq!(
            *attempts.lock().unwrap(),
            vec![(ranges[0].host_addr, 0), (ranges[0].host_addr, 0)]
        );
    }

    #[test]
    fn cow_restore_maps_data_and_reads_holes_as_zero() {
        let page = get_page_size();
        let gm = GuestMemory::from_ranges(&[(GuestAddress(0), (2 * page) as usize)]).unwrap();

        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![0xabu8; page as usize]).unwrap();
        file.set_len(2 * page).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();

        let mut table = MemoryRangeTable::default();
        table.push(MemoryRange {
            gpa: 0,
            length: 2 * page,
        });

        assert!(is_restore_cow_compatible(&gm, &table));
        do_mmap_cow_saved_regions(&gm, &file, &table, false).unwrap();

        assert_eq!(gm.read_obj::<u8>(GuestAddress(0)).unwrap(), 0xab);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(page - 1)).unwrap(), 0xab);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(page)).unwrap(), 0);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(2 * page - 1)).unwrap(), 0);

        // Copy-on-write: guest writes must not reach the file.
        gm.write_obj::<u8>(0x5a, GuestAddress(0)).unwrap();
        let mut back = [0u8; 1];
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_exact(&mut back).unwrap();
        assert_eq!(back[0], 0xab);
    }

    #[test]
    fn cow_snapshot_writes_private_pages_over_the_source() {
        let page = get_page_size();
        let gm = GuestMemory::from_ranges(&[(GuestAddress(0), (16 * page) as usize)]).unwrap();
        let mut file = tempfile::tempfile().unwrap();
        for i in 0..16u8 {
            file.write_all(&vec![i + 1; page as usize]).unwrap();
        }
        let mut ranges = MemoryRangeTable::default();
        ranges.push(MemoryRange {
            gpa: 0,
            length: 16 * page,
        });
        do_mmap_cow_saved_regions(&gm, &file, &ranges, false).unwrap();
        let source = CowSource {
            file,
            ranges,
            pagemap: PageMap::open().unwrap(),
        };
        gm.write_obj::<u8>(0x55, GuestAddress(page)).unwrap();
        gm.write_obj::<u8>(0x77, GuestAddress(12 * page + 9))
            .unwrap();

        let mut snapshot = tempfile::tempfile().unwrap();
        let mut content = vec![0u8; (16 * page) as usize];
        source.file.read_exact_at(&mut content, 0).unwrap();
        snapshot.write_all(&content).unwrap();
        write_private_pages(&gm, &source, &mut snapshot).unwrap();

        let mut got = vec![0u8; (16 * page) as usize];
        snapshot.read_exact_at(&mut got, 0).unwrap();
        let mut want = vec![0u8; (16 * page) as usize];
        gm.read_slice(&mut want, GuestAddress(0)).unwrap();
        assert!(got == want);
        assert_eq!(content[page as usize], 2);
        assert_eq!(got[page as usize], 0x55);
    }

    #[test]
    fn cow_restore_detects_saved_ranges_in_virtio_mem_windows() {
        let mut table = MemoryRangeTable::default();
        table.push(MemoryRange {
            gpa: 0,
            length: 0x1000_0000,
        });
        // Boot RAM only: a virtio-mem window above it does not overlap.
        let windows = [(0x1_0000_0000u64, 0x4_0000_0000u64)];
        assert!(!saved_ranges_overlap(&table, &windows));
        assert!(!saved_ranges_overlap(&table, &[]));
        // A touching-but-disjoint window does not overlap.
        assert!(!saved_ranges_overlap(&table, &[(0x1000_0000, 0x1000)]));
        // A plugged block inside the window does.
        table.push(MemoryRange {
            gpa: 0x1_0020_0000,
            length: 0x20_0000,
        });
        assert!(saved_ranges_overlap(&table, &windows));
    }

    #[test]
    fn cow_restore_overlap_edge_cases() {
        let one = |gpa: u64, length: u64| {
            let mut table = MemoryRangeTable::default();
            table.push(MemoryRange { gpa, length });
            table
        };
        let (start, len) = (0x1_0000_0000u64, 0x4000_0000u64);
        let window = [(start, len)];
        // Starts below the window and ends inside it.
        assert!(saved_ranges_overlap(&one(start - 0x1000, 0x2000), &window));
        // Ends exactly at the window's start.
        assert!(!saved_ranges_overlap(&one(start - 0x1000, 0x1000), &window));
        // Starts exactly at the window's end.
        assert!(!saved_ranges_overlap(&one(start + len, 0x1000), &window));
        // Last byte of the window, and first byte past it.
        assert!(saved_ranges_overlap(
            &one(start + len - 0x1000, 0x2000),
            &window
        ));
        // A window entirely inside a larger range.
        assert!(saved_ranges_overlap(&one(0, start + len + 0x1000), &window));
        // Several windows: a range between them overlaps neither, a range in
        // the second one is found.
        let windows = [(start, len), (0x2_0000_0000, len)];
        assert!(!saved_ranges_overlap(&one(start + len, 0x1000), &windows));
        assert!(saved_ranges_overlap(&one(0x2_0010_0000, 0x1000), &windows));
        // Several ranges, only the last of which overlaps.
        let mut table = one(0, 0x1000);
        table.push(MemoryRange {
            gpa: 0x1_8000_0000,
            length: 0x1000,
        });
        assert!(!saved_ranges_overlap(&table, &windows));
        table.push(MemoryRange {
            gpa: 0x2_3fff_f000,
            length: 0x1000,
        });
        assert!(saved_ranges_overlap(&table, &windows));
    }

    // Boot RAM plus a virtio-mem region, laid out the way a restore lays
    // them out: boot RAM in the zone's regions, the virtio-mem region in its
    // virtio_mem_zone, nothing plugged. Built by hand because
    // restore_memory_regions_and_zones() needs a hypervisor VM.
    fn restore_zone_with_virtio_mem() -> (GuestMemory, MemoryZones) {
        const MIB: u64 = 1 << 20;
        let region = |gpa: u64, size: u64| {
            Arc::new(GuestRegion::from(
                vm_memory::GuestRegionMmap::<AtomicBitmap>::from_range(
                    GuestAddress(gpa),
                    size as usize,
                    None,
                )
                .unwrap(),
            ))
        };
        let boot = region(0, 4 * MIB);
        let vmem = region(16 * MIB, 8 * MIB);
        let mut zone = MemoryZone::new(false, false, get_page_size(), false);
        zone.regions.push(Arc::clone(&boot));
        zone.virtio_mem_zone = Some(VirtioMemZone {
            region: Arc::clone(&vmem),
            virtio_device: None,
            hotplugged_size: 0,
            hugepages: false,
            blocks_state: Arc::new(Mutex::new(BlocksState::new(vmem.len()))),
        });
        let mut zones = MemoryZones::new();
        zones.insert("mem0".to_string(), zone);
        (
            GuestMemory::from_arc_regions(vec![boot, vmem]).unwrap(),
            zones,
        )
    }

    #[test]
    fn cow_restore_falls_back_for_saved_ranges_in_virtio_mem_zone() {
        const MIB: u64 = 1 << 20;
        let (_gm, zones) = restore_zone_with_virtio_mem();
        let vmem = zones["mem0"].virtio_mem_zone.as_ref().unwrap();
        assert_eq!(vmem.region.start_addr(), GuestAddress(16 * MIB));
        // Nothing plugged: the saved ranges are boot RAM only, so CoW applies.
        let mut table = MemoryRangeTable::default();
        table.push(MemoryRange {
            gpa: 0,
            length: 4 * MIB,
        });
        assert!(vmem.plugged_ranges().ranges().is_empty());
        assert!(!saved_ranges_in_virtio_mem(&zones, &table));
        assert!(!saved_ranges_in_virtio_mem(&MemoryZones::new(), &table));
        // A block still plugged at snapshot time is saved: fall back to copy.
        table.push(MemoryRange {
            gpa: 18 * MIB,
            length: 2 * MIB,
        });
        assert!(saved_ranges_in_virtio_mem(&zones, &table));
    }

    #[test]
    fn copy_on_access_falls_back_for_saved_ranges_in_virtio_mem_zone() {
        const MIB: u64 = 1 << 20;
        let (_gm, zones) = restore_zone_with_virtio_mem();
        // Nothing plugged: copy-on-access applies.
        let mut table = MemoryRangeTable::default();
        table.push(MemoryRange {
            gpa: 0,
            length: 4 * MIB,
        });
        assert_eq!(
            effective_restore_mode(MemoryRestoreMode::CopyOnAccess, &zones, &table),
            MemoryRestoreMode::CopyOnAccess
        );
        // A block still plugged at snapshot time: fall back to copy. The
        // other modes are left alone.
        table.push(MemoryRange {
            gpa: 18 * MIB,
            length: 2 * MIB,
        });
        assert_eq!(
            effective_restore_mode(MemoryRestoreMode::CopyOnAccess, &zones, &table),
            MemoryRestoreMode::Copy
        );
        for mode in [
            MemoryRestoreMode::Copy,
            MemoryRestoreMode::OnDemand,
            MemoryRestoreMode::CopyOnWrite,
        ] {
            assert_eq!(effective_restore_mode(mode, &zones, &table), mode);
        }
    }

    // A snapshot memory file holding `chunks` of (byte, length) in order.
    fn snapshot_file(chunks: &[(u8, u64)]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        for &(byte, len) in chunks {
            file.write_all(&vec![byte; len as usize]).unwrap();
        }
        file
    }

    #[test]
    fn uffd_restore_refuses_snapshot_file_shorter_than_ranges() {
        const MIB: u64 = 1 << 20;
        let mut table = MemoryRangeTable::default();
        table.push(MemoryRange {
            gpa: 0,
            length: 4 * MIB,
        });
        table.push(MemoryRange {
            gpa: 18 * MIB,
            length: 2 * MIB,
        });
        // As long as the ranges, or longer: accepted.
        for len in [6 * MIB, 6 * MIB + 4096] {
            let file = snapshot_file(&[(0xab, len)]);
            check_snapshot_file_covers_ranges(file.as_file(), &table).unwrap();
        }
        // One page short of the second range's end: refused.
        let file = snapshot_file(&[(0xab, 6 * MIB - 4096)]);
        match check_snapshot_file_covers_ranges(file.as_file(), &table) {
            Err(Error::SnapshotRead(e)) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            other => panic!("short file accepted: {other:?}"),
        }
        // Range lengths that overflow a file offset: refused, not wrapped.
        table.push(MemoryRange {
            gpa: 32 * MIB,
            length: u64::MAX,
        });
        let file = snapshot_file(&[(0xab, 6 * MIB)]);
        match check_snapshot_file_covers_ranges(file.as_file(), &table) {
            Err(Error::SnapshotRead(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            other => panic!("overflowing ranges accepted: {other:?}"),
        }
    }

    // Whether the host mapping containing `gpa` is backed by a file, from the
    // inode column of /proc/self/maps.
    fn gpa_is_file_backed(gm: &GuestMemory, gpa: u64) -> bool {
        let host = gm.get_host_address(GuestAddress(gpa)).unwrap() as usize;
        let maps = fs::read_to_string("/proc/self/maps").unwrap();
        maps.lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let (lo, hi) = fields.next()?.split_once('-')?;
                let lo = usize::from_str_radix(lo, 16).ok()?;
                let hi = usize::from_str_radix(hi, 16).ok()?;
                // Skip perms, offset and dev to reach the inode.
                (lo..hi).contains(&host).then(|| fields.nth(3) != Some("0"))
            })
            .expect("guest address not found in /proc/self/maps")
    }

    // What virtio-mem does to an unplugged block.
    fn discard(gm: &GuestMemory, gpa: u64, len: u64) {
        let host = gm.get_host_address(GuestAddress(gpa)).unwrap();
        // SAFETY: host/len name guest RAM inside a single region of gm.
        let ret = unsafe { libc::madvise(host.cast(), len as usize, libc::MADV_DONTNEED) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn cow_restore_copies_saved_ranges_in_virtio_mem() {
        const MIB: u64 = 1 << 20;
        let (gm, zones) = restore_zone_with_virtio_mem();
        // Boot RAM, then a block that was still plugged at snapshot time.
        let file = snapshot_file(&[(0xab, 4 * MIB), (0xcd, 2 * MIB)]);
        let mut table = MemoryRangeTable::default();
        table.push(MemoryRange {
            gpa: 0,
            length: 4 * MIB,
        });
        table.push(MemoryRange {
            gpa: 18 * MIB,
            length: 2 * MIB,
        });
        // The region checks accept the block: only the virtio-mem check
        // keeps it from being mapped from the file.
        assert!(is_restore_cow_compatible(&gm, &table));
        MemoryManager::cow_map_saved_regions(&gm, &zones, false, file.path().to_path_buf(), &table)
            .unwrap();
        // The eager copy ran: nothing is file-backed and the data is in place.
        assert!(!gpa_is_file_backed(&gm, 0));
        assert!(!gpa_is_file_backed(&gm, 18 * MIB));
        assert_eq!(gm.read_obj::<u8>(GuestAddress(0)).unwrap(), 0xab);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(4 * MIB - 1)).unwrap(), 0xab);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(18 * MIB)).unwrap(), 0xcd);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(20 * MIB - 1)).unwrap(), 0xcd);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(16 * MIB)).unwrap(), 0);
    }

    #[test]
    fn cow_restore_keeps_unplugged_virtio_mem_anonymous() {
        const MIB: u64 = 1 << 20;
        let block = 18 * MIB;

        // Nothing plugged: boot RAM is mapped from the file, and a block the
        // guest plugs, writes and unplugs after the restore reads as zero.
        let (gm, zones) = restore_zone_with_virtio_mem();
        let file = snapshot_file(&[(0xab, 4 * MIB)]);
        let mut table = MemoryRangeTable::default();
        table.push(MemoryRange {
            gpa: 0,
            length: 4 * MIB,
        });
        MemoryManager::cow_map_saved_regions(&gm, &zones, false, file.path().to_path_buf(), &table)
            .unwrap();
        assert!(gpa_is_file_backed(&gm, 0));
        assert!(!gpa_is_file_backed(&gm, block));
        assert_eq!(gm.read_obj::<u8>(GuestAddress(0)).unwrap(), 0xab);
        gm.write_obj::<u8>(0x5a, GuestAddress(block)).unwrap();
        discard(&gm, block, 2 * MIB);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(block)).unwrap(), 0);

        // A block still plugged at snapshot time: restored with its content,
        // and once the guest unplugs it, it reads as zero rather than as the
        // snapshot's copy.
        let (gm, zones) = restore_zone_with_virtio_mem();
        let file = snapshot_file(&[(0xab, 4 * MIB), (0xcd, 2 * MIB)]);
        table.push(MemoryRange {
            gpa: block,
            length: 2 * MIB,
        });
        MemoryManager::cow_map_saved_regions(&gm, &zones, false, file.path().to_path_buf(), &table)
            .unwrap();
        assert_eq!(gm.read_obj::<u8>(GuestAddress(block)).unwrap(), 0xcd);
        gm.write_obj::<u8>(0x5a, GuestAddress(block)).unwrap();
        discard(&gm, block, 2 * MIB);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(block)).unwrap(), 0);
    }

    // Why plugged virtio-mem blocks must not be CoW-mapped: unplug discards
    // with MADV_DONTNEED, which on a private file map drops the private copy
    // and re-exposes the snapshot page instead of zeroing it.
    #[test]
    fn cow_restore_dontneed_reverts_to_file_content() {
        let page = get_page_size();
        let gm = GuestMemory::from_ranges(&[(GuestAddress(0), page as usize)]).unwrap();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![0xabu8; page as usize]).unwrap();
        let mut table = MemoryRangeTable::default();
        table.push(MemoryRange {
            gpa: 0,
            length: page,
        });
        do_mmap_cow_saved_regions(&gm, &file, &table, false).unwrap();
        gm.write_obj::<u8>(0x5a, GuestAddress(0)).unwrap();
        let host = gm.get_host_address(GuestAddress(0)).unwrap();
        // SAFETY: host/page name the private mapping installed above.
        let ret = unsafe { libc::madvise(host.cast(), page as usize, libc::MADV_DONTNEED) };
        assert_eq!(ret, 0);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(0)).unwrap(), 0xab);
    }

    #[test]
    fn cow_restore_rejects_unaligned_or_out_of_region_ranges() {
        let page = get_page_size();
        let gm = GuestMemory::from_ranges(&[(GuestAddress(0), page as usize)]).unwrap();

        let mut unaligned = MemoryRangeTable::default();
        unaligned.push(MemoryRange {
            gpa: 1,
            length: page,
        });
        assert!(!is_restore_cow_compatible(&gm, &unaligned));

        let mut spanning = MemoryRangeTable::default();
        spanning.push(MemoryRange {
            gpa: 0,
            length: 2 * page,
        });
        assert!(!is_restore_cow_compatible(&gm, &spanning));
    }

    #[test]
    fn cow_restore_rejects_overlapping_ranges() {
        let page = get_page_size();
        let gm = GuestMemory::from_ranges(&[(GuestAddress(0), (4 * page) as usize)]).unwrap();
        let table = |ranges: &[(u64, u64)]| {
            let mut table = MemoryRangeTable::default();
            for &(gpa, length) in ranges {
                table.push(MemoryRange { gpa, length });
            }
            table
        };

        // Adjacent ranges, in either order, and an empty one are fine.
        for ok in [
            table(&[(0, page), (page, 3 * page)]),
            table(&[(2 * page, 2 * page), (0, 2 * page)]),
            table(&[(0, 2 * page), (page, 0), (2 * page, page)]),
        ] {
            assert!(is_restore_cow_compatible(&gm, &ok));
        }
        // Ranges sharing even one page are not, whatever their order.
        for overlapping in [
            table(&[(0, 2 * page), (page, 2 * page)]),
            table(&[(2 * page, 2 * page), (0, 3 * page)]),
            table(&[(0, 4 * page), (page, page)]),
            table(&[(page, page), (3 * page, page), (page, page)]),
        ] {
            assert!(!is_restore_cow_compatible(&gm, &overlapping));
        }
    }

    #[test]
    fn cow_restore_rejects_file_backed_region() {
        let page = get_page_size();
        let backing = tempfile::tempfile().unwrap();
        backing.set_len(page).unwrap();
        let region = MmapRegion::build(
            Some(FileOffset::new(backing, 0)),
            page as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
        )
        .unwrap();
        let gm = GuestMemory::from_regions(vec![
            vm_memory::GuestRegionMmap::new(region, GuestAddress(0))
                .unwrap()
                .into(),
        ])
        .unwrap();

        let mut table = MemoryRangeTable::default();
        table.push(MemoryRange {
            gpa: 0,
            length: page,
        });
        assert!(!is_restore_cow_compatible(&gm, &table));
    }

    #[test]
    fn cow_restore_honors_region_reserve_and_thp() {
        let page = get_page_size();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![0xcdu8; page as usize]).unwrap();

        for extra_flags in [0, libc::MAP_NORESERVE] {
            let region = MmapRegion::build(
                None,
                page as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | extra_flags,
            )
            .unwrap();
            let gm = GuestMemory::from_regions(vec![
                vm_memory::GuestRegionMmap::new(region, GuestAddress(0))
                    .unwrap()
                    .into(),
            ])
            .unwrap();

            let mut table = MemoryRangeTable::default();
            table.push(MemoryRange {
                gpa: 0,
                length: page,
            });
            do_mmap_cow_saved_regions(&gm, &file, &table, true).unwrap();
            assert_eq!(gm.read_obj::<u8>(GuestAddress(0)).unwrap(), 0xcd);
        }
    }

    const MIB: u64 = 1 << 20;

    // Every page-aligned hole in the first `len` bytes of `file`, or None if
    // SEEK_HOLE is unsupported.
    fn all_holes(file: &File, len: u64) -> Option<Vec<(u64, u64)>> {
        let mut holes = Vec::new();
        cow_file_holes(file, 0, len, get_page_size(), |off, len| {
            holes.push((off, len));
        })
        .ok()?;
        Some(holes)
    }

    // A sparse file of 8 MiB: data [0, 2) MiB, a 3 MiB hole, data [5, 6),
    // a 1 MiB hole, data [7, 8). Mapped over 10 MiB, [8, 10) lies past EOF.
    // None unless SEEK_HOLE reports exactly those holes.
    fn sparse_snapshot_file() -> Option<File> {
        use std::os::unix::fs::FileExt;

        let file = tempfile::tempfile().unwrap();
        file.set_len(8 * MIB).unwrap();
        for (byte, off, len) in [
            (0xab, 0, 2 * MIB),
            (0xcd, 5 * MIB, MIB),
            (0xef, 7 * MIB, MIB),
        ] {
            file.write_all_at(&vec![byte; len as usize], off).unwrap();
        }
        let holes = [(2 * MIB, 3 * MIB), (6 * MIB, MIB)];
        let seen = all_holes(&file, 8 * MIB)?;
        if seen != holes {
            eprintln!("skipped: SEEK_HOLE reports {seen:x?}, not the holes written {holes:x?}");
            return None;
        }
        Some(file)
    }

    // Whether the VMA holding `gpa` carries `flag` in its smaps VmFlags.
    fn gpa_has_vm_flag(gm: &GuestMemory, gpa: u64, flag: &str) -> bool {
        let host = gm.get_host_address(GuestAddress(gpa)).unwrap() as usize;
        let smaps = fs::read_to_string("/proc/self/smaps").unwrap();
        let mut inside = false;
        for line in smaps.lines() {
            if let Some((lo, rest)) = line.split_once('-')
                && let Some(hi) = rest.split_whitespace().next()
                && let (Ok(lo), Ok(hi)) =
                    (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
            {
                inside = (lo..hi).contains(&host);
            } else if inside && let Some(flags) = line.strip_prefix("VmFlags:") {
                return flags.split_whitespace().any(|f| f == flag);
            }
        }
        panic!("guest address not found in /proc/self/smaps");
    }

    #[test]
    fn cow_restore_maps_file_holes_anonymous() {
        use std::os::unix::fs::FileExt;

        let Some(file) = sparse_snapshot_file() else {
            return;
        };
        let gm = GuestMemory::from_ranges(&[(GuestAddress(0), (10 * MIB) as usize)]).unwrap();
        let mut table = MemoryRangeTable::default();
        table.push(MemoryRange {
            gpa: 0,
            length: 10 * MIB,
        });
        do_mmap_cow_saved_regions(&gm, &file, &table, true).unwrap();

        // Data reads the file's bytes, holes and past-EOF read zero.
        for (gpa, byte) in [
            (0, 0xab),
            (2 * MIB - 1, 0xab),
            (2 * MIB, 0),
            (5 * MIB - 1, 0),
            (5 * MIB, 0xcd),
            (6 * MIB, 0),
            (7 * MIB, 0xef),
            (8 * MIB - 1, 0xef),
            (8 * MIB, 0),
            (10 * MIB - 1, 0),
        ] {
            assert_eq!(gm.read_obj::<u8>(GuestAddress(gpa)).unwrap(), byte);
        }

        // Every hole, the 1 MiB one too, is anonymous; data stays mapped
        // from the file.
        assert!(gpa_is_file_backed(&gm, 0));
        assert!(!gpa_is_file_backed(&gm, 2 * MIB));
        assert!(!gpa_is_file_backed(&gm, 5 * MIB - 1));
        assert!(gpa_is_file_backed(&gm, 5 * MIB));
        assert!(!gpa_is_file_backed(&gm, 6 * MIB));
        assert!(gpa_is_file_backed(&gm, 7 * MIB));
        assert!(!gpa_is_file_backed(&gm, 8 * MIB));

        // The THP advice covers the anonymous ranges as well.
        if Path::new("/sys/kernel/mm/transparent_hugepage").exists() {
            assert!(gpa_has_vm_flag(&gm, 0, "hg"));
            assert!(gpa_has_vm_flag(&gm, 2 * MIB, "hg"));
            assert!(gpa_has_vm_flag(&gm, 8 * MIB, "hg"));
        }

        // A write into a remapped hole is kept and never reaches the file,
        // which keeps its hole; a discard reads back zero.
        gm.write_obj::<u8>(0x5a, GuestAddress(3 * MIB)).unwrap();
        assert_eq!(gm.read_obj::<u8>(GuestAddress(3 * MIB)).unwrap(), 0x5a);
        let mut back = [0xffu8; 1];
        file.read_exact_at(&mut back, 3 * MIB).unwrap();
        assert_eq!(back[0], 0);
        assert_eq!(
            next_data_extent(file.as_fd(), 2 * MIB, 5 * MIB).unwrap(),
            None
        );
        assert_eq!(file.metadata().unwrap().len(), 8 * MIB);
        discard(&gm, 3 * MIB, get_page_size());
        assert_eq!(gm.read_obj::<u8>(GuestAddress(3 * MIB)).unwrap(), 0);
    }

    // Guest RAM with `file` mapped privately over it, as the copy-on-write
    // restore maps it, before any hole is remapped.
    fn private_file_mapping(file: &File, len: u64) -> GuestMemory {
        let gm = GuestMemory::from_ranges(&[(GuestAddress(0), len as usize)]).unwrap();
        let host = gm.get_host_address(GuestAddress(0)).unwrap();
        // SAFETY: host/len name the whole anonymous region just created.
        let ret = unsafe {
            libc::mmap(
                host.cast(),
                len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_NORESERVE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(ret, libc::MAP_FAILED);
        gm
    }

    fn whole_mapping(gm: &GuestMemory) -> CowMapping {
        CowMapping {
            host: gm.get_host_address(GuestAddress(0)).unwrap(),
            len: gm.find_region(GuestAddress(0)).unwrap().len() as usize,
            file_offset: 0,
            map_flags: libc::MAP_NORESERVE,
        }
    }

    fn remap_holes(gm: &GuestMemory, file: &File, limits: HoleRemapLimits) -> HoleRemapReport {
        let mut reports =
            remap_cow_holes(&[whole_mapping(gm)], file, limits, |addr, len, flags| {
                // SAFETY: the range lies in gm's mapping, which the test owns.
                unsafe { map_anon_fixed(addr, len, flags) }
            })
            .unwrap();
        assert_eq!(reports.len(), 1);
        reports.pop().unwrap()
    }

    // Every hole found is remapped or counted as skipped for one reason.
    fn assert_holes_add_up(report: &HoleRemapReport) {
        assert_eq!(
            report.found,
            report.holes + report.skipped_small + report.skipped_cap + report.skipped_failed,
            "{report}"
        );
    }

    // A file of `len` bytes of data with `holes` punched out. None unless
    // SEEK_HOLE reports exactly those holes, as on a filesystem that tracks
    // holes at a coarser grain (ZFS) it does not.
    fn file_with_holes(len: u64, holes: &[(u64, u64)]) -> Option<File> {
        use std::os::unix::fs::FileExt;

        let file = tempfile::tempfile().unwrap();
        file.write_all_at(&vec![0x77u8; len as usize], 0).unwrap();
        for &(off, hole_len) in holes {
            // SAFETY: a plain syscall on an fd the test owns.
            let ret = unsafe {
                libc::fallocate(
                    file.as_raw_fd(),
                    libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                    off as libc::off_t,
                    hole_len as libc::off_t,
                )
            };
            if ret != 0 {
                eprintln!(
                    "skipped: cannot punch holes: {}",
                    io::Error::last_os_error()
                );
                return None;
            }
        }
        let seen = all_holes(&file, len)?;
        if seen != holes {
            eprintln!("skipped: SEEK_HOLE reports {seen:x?}, not the holes punched {holes:x?}");
            return None;
        }
        Some(file)
    }

    #[test]
    fn cow_hole_remap_reports_and_honors_limits() {
        let Some(file) = sparse_snapshot_file() else {
            return;
        };

        let gm = private_file_mapping(&file, 10 * MIB);
        let report = remap_holes(&gm, &file, HoleRemapLimits::default());
        assert_eq!(
            report,
            HoleRemapReport {
                extents: 3,
                found: 3,
                skipped_small: 0,
                skipped_cap: 0,
                skipped_failed: 0,
                holes: 3,
                bytes: 6 * MIB,
                fallback: None,
            }
        );

        // Below the minimum size every hole stays mapped from the file.
        let gm = private_file_mapping(&file, 8 * MIB);
        let limits = HoleRemapLimits {
            min_size: 4 * MIB,
            ..Default::default()
        };
        let report = remap_holes(&gm, &file, limits);
        assert_eq!(
            (report.extents, report.found, report.skipped_small),
            (3, 2, 2)
        );
        assert_eq!((report.holes, report.bytes), (0, 0));
        assert_eq!(report.fallback, None);
        assert_holes_add_up(&report);
        assert!(gpa_is_file_backed(&gm, 2 * MIB));

        // Over the budget, the largest holes are remapped and the rest stay
        // mapped from the file.
        let gm = private_file_mapping(&file, 10 * MIB);
        let limits = HoleRemapLimits {
            max_holes: 2,
            ..Default::default()
        };
        let report = remap_holes(&gm, &file, limits);
        assert_eq!((report.found, report.skipped_cap), (3, 1));
        assert_eq!((report.holes, report.bytes), (2, 5 * MIB));
        assert_eq!(report.fallback, None);
        assert_holes_add_up(&report);
        assert!(!gpa_is_file_backed(&gm, 2 * MIB));
        assert!(gpa_is_file_backed(&gm, 6 * MIB));
        assert!(!gpa_is_file_backed(&gm, 8 * MIB));
        assert_eq!(gm.read_obj::<u8>(GuestAddress(0)).unwrap(), 0xab);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(6 * MIB)).unwrap(), 0);

        // With no budget, every hole stays mapped from the file.
        let gm = private_file_mapping(&file, 10 * MIB);
        let limits = HoleRemapLimits {
            max_holes: 0,
            ..Default::default()
        };
        let report = remap_holes(&gm, &file, limits);
        assert_eq!((report.skipped_cap, report.holes), (3, 0));
        assert_holes_add_up(&report);
        assert!(gpa_is_file_backed(&gm, 2 * MIB));
    }

    #[test]
    fn cow_hole_remap_counts_holes_left_after_a_failure() {
        let Some(file) = sparse_snapshot_file() else {
            return;
        };
        let gm = private_file_mapping(&file, 10 * MIB);
        // The second remap fails, without touching the mapping.
        let mut calls = 0;
        let mut reports = remap_cow_holes(
            &[whole_mapping(&gm)],
            &file,
            HoleRemapLimits::default(),
            |addr, len, flags| {
                calls += 1;
                if calls == 2 {
                    return Err(io::Error::other("injected"));
                }
                // SAFETY: the range lies in gm's mapping, which the test owns.
                unsafe { map_anon_fixed(addr, len, flags) }
            },
        )
        .unwrap();
        assert_eq!(calls, 2);
        let report = reports.pop().unwrap();
        assert_eq!(
            report,
            HoleRemapReport {
                extents: 3,
                found: 3,
                skipped_small: 0,
                skipped_cap: 0,
                skipped_failed: 2,
                holes: 1,
                bytes: 3 * MIB,
                fallback: Some("mmap_failed"),
            }
        );
        assert_holes_add_up(&report);
        // The hole that failed is mapped from the file again, and still
        // reads zero; the one never tried is untouched.
        assert!(!gpa_is_file_backed(&gm, 2 * MIB));
        assert!(gpa_is_file_backed(&gm, 6 * MIB));
        assert_eq!(gm.read_obj::<u8>(GuestAddress(6 * MIB)).unwrap(), 0);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(7 * MIB)).unwrap(), 0xef);
        assert!(gpa_is_file_backed(&gm, 8 * MIB));
    }

    #[test]
    fn cow_hole_remap_keeps_the_file_mapping_when_out_of_vmas() {
        let Some(file) = sparse_snapshot_file() else {
            return;
        };
        let gm = private_file_mapping(&file, 10 * MIB);
        // As at vm.max_map_count: the anonymous remap fails with ENOMEM and
        // leaves the file mapping, and so would any other MAP_FIXED over it.
        let mut anon_calls = 0;
        let mut file_calls = 0;
        let mut reports = remap_cow_holes_with(
            &[whole_mapping(&gm)],
            &file,
            HoleRemapLimits::default(),
            |_, _, _| {
                anon_calls += 1;
                Err(io::Error::from_raw_os_error(libc::ENOMEM))
            },
            |addr, len, flags, off| {
                file_calls += 1;
                if flags & libc::MAP_FIXED != 0 {
                    return Err(io::Error::from_raw_os_error(libc::ENOMEM));
                }
                // SAFETY: the range lies in gm's mapping, which the test
                // owns, and the flags carry no MAP_FIXED.
                let ret = unsafe {
                    libc::mmap(
                        addr.cast(),
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        flags,
                        file.as_raw_fd(),
                        off,
                    )
                };
                if ret == libc::MAP_FAILED {
                    return Err(io::Error::last_os_error());
                }
                Ok(ret.cast())
            },
        )
        .unwrap();
        assert_eq!((anon_calls, file_calls), (1, 1));
        let report = reports.pop().unwrap();
        assert_eq!(
            report,
            HoleRemapReport {
                extents: 3,
                found: 3,
                skipped_failed: 3,
                fallback: Some("mmap_failed"),
                ..Default::default()
            }
        );
        assert_holes_add_up(&report);
        // Every hole is still mapped from the file, and the range reads the
        // file's data (past the file's end, at 8 MiB, it would fault).
        for gpa in [2 * MIB, 6 * MIB, 8 * MIB] {
            assert!(gpa_is_file_backed(&gm, gpa));
        }
        assert_eq!(gm.read_obj::<u8>(GuestAddress(2 * MIB)).unwrap(), 0);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(6 * MIB)).unwrap(), 0);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(0)).unwrap(), 0xab);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(5 * MIB)).unwrap(), 0xcd);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(7 * MIB)).unwrap(), 0xef);
    }

    #[test]
    fn cow_hole_remap_fails_when_the_kernel_ignores_fixed_noreplace() {
        use std::ptr;

        let Some(file) = sparse_snapshot_file() else {
            return;
        };
        let gm = private_file_mapping(&file, 10 * MIB);
        // A kernel before 4.17 takes MAP_FIXED_NOREPLACE as a hint and maps
        // the file elsewhere; whether the hole is still mapped is then
        // unknown, so the restore fails.
        let mut file_calls = 0;
        let res = remap_cow_holes_with(
            &[whole_mapping(&gm)],
            &file,
            HoleRemapLimits::default(),
            |_, _, _| Err(io::Error::from_raw_os_error(libc::ENOMEM)),
            |_, len, flags, off| {
                file_calls += 1;
                // SAFETY: no address and no MAP_FIXED: the kernel picks a
                // free range, which the code under test unmaps again.
                let ret = unsafe {
                    libc::mmap(
                        ptr::null_mut(),
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        flags & !libc::MAP_FIXED_NOREPLACE,
                        file.as_raw_fd(),
                        off,
                    )
                };
                if ret == libc::MAP_FAILED {
                    return Err(io::Error::last_os_error());
                }
                Ok(ret.cast())
            },
        );
        assert!(matches!(res, Err(Error::SnapshotMmap(_))), "{res:?}");
        assert_eq!(file_calls, 1);
        // The guest's file mapping was left alone.
        assert!(gpa_is_file_backed(&gm, 2 * MIB));
        assert_eq!(gm.read_obj::<u8>(GuestAddress(0)).unwrap(), 0xab);
    }

    #[test]
    fn cow_hole_remap_failure_skips_the_holes_of_later_ranges() {
        let kib = 1 << 10;
        // Range 0 ([0, 2) MiB) and range 1 ([2, 4) MiB) have two holes each;
        // the second remap, range 0's last, fails, so range 1's are skipped.
        let holes = [
            (256 * kib, 64 * kib),
            (MIB, 128 * kib),
            (2 * MIB + 256 * kib, 64 * kib),
            (3 * MIB, 256 * kib),
        ];
        let Some(file) = file_with_holes(4 * MIB, &holes) else {
            return;
        };
        let gm = private_file_mapping(&file, 4 * MIB);
        let whole = whole_mapping(&gm);
        let mappings = [
            CowMapping {
                len: (2 * MIB) as usize,
                ..whole
            },
            CowMapping {
                // SAFETY: 2 MiB lies inside gm's 4 MiB mapping.
                host: unsafe { whole.host.add((2 * MIB) as usize) },
                len: (2 * MIB) as usize,
                file_offset: 2 * MIB,
                ..whole
            },
        ];
        let mut calls = 0;
        let reports = remap_cow_holes(
            &mappings,
            &file,
            HoleRemapLimits::default(),
            |addr, len, flags| {
                calls += 1;
                if calls == 2 {
                    return Err(io::Error::other("injected"));
                }
                // SAFETY: the range lies in gm's mapping, which the test owns.
                unsafe { map_anon_fixed(addr, len, flags) }
            },
        )
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(
            reports,
            vec![
                HoleRemapReport {
                    extents: 3,
                    found: 2,
                    skipped_failed: 1,
                    holes: 1,
                    bytes: 64 * kib,
                    fallback: Some("mmap_failed"),
                    ..Default::default()
                },
                HoleRemapReport {
                    extents: 3,
                    found: 2,
                    skipped_failed: 2,
                    fallback: Some("mmap_failed"),
                    ..Default::default()
                },
            ]
        );
        for report in &reports {
            assert_holes_add_up(report);
        }
        assert!(!gpa_is_file_backed(&gm, 256 * kib));
        for &(gpa, _) in &holes[1..] {
            assert!(gpa_is_file_backed(&gm, gpa));
            assert_eq!(gm.read_obj::<u8>(GuestAddress(gpa)).unwrap(), 0);
        }
        assert_eq!(gm.read_obj::<u8>(GuestAddress(2 * MIB)).unwrap(), 0x77);
    }

    #[test]
    fn cow_hole_remap_covers_small_holes() {
        let page = get_page_size();
        let kib = 1 << 10;
        if page >= 64 * kib {
            eprintln!("skipped: a one-page hole is not small with {page}-byte pages");
            return;
        }
        // One-page and 64 KiB holes in turn, each after a data page, in a
        // file that ends in data: only the 64 KiB holes are remapped.
        let mut off = 0;
        let mut small = Vec::new();
        let mut big = Vec::new();
        for i in 0..8 {
            off += page;
            if i % 2 == 0 {
                small.push((off, page));
                off += page;
            } else {
                big.push((off, 64 * kib));
                off += 64 * kib;
            }
        }
        off += page;
        let mut holes: Vec<_> = small.iter().chain(&big).copied().collect();
        holes.sort_unstable();
        let Some(file) = file_with_holes(off, &holes) else {
            return;
        };
        // Mapped past EOF, which adds one more hole.
        let len = off.next_multiple_of(2 * MIB);

        let gm = private_file_mapping(&file, len);
        let report = remap_holes(&gm, &file, HoleRemapLimits::default());
        assert_eq!(report.extents, 9);
        assert_eq!(report.found, 9);
        assert_eq!(report.skipped_small, 4);
        assert_eq!(report.holes, 5);
        assert_eq!(report.bytes, 4 * 64 * kib + (len - off));
        assert_eq!(report.fallback, None);
        assert_holes_add_up(&report);
        for &(gpa, _) in &small {
            assert!(gpa_is_file_backed(&gm, gpa));
        }
        for &(gpa, _) in &big {
            assert!(!gpa_is_file_backed(&gm, gpa));
            assert!(!gpa_is_file_backed(&gm, gpa + 64 * kib - 1));
            assert!(gpa_is_file_backed(&gm, gpa + 64 * kib));
            assert_eq!(gm.read_obj::<u8>(GuestAddress(gpa)).unwrap(), 0);
        }
        assert_eq!(gm.read_obj::<u8>(GuestAddress(0)).unwrap(), 0x77);
    }

    #[test]
    fn cow_hole_remap_prefers_largest_across_ranges() {
        let kib = 1 << 10;
        // Range 0 ([0, 2) MiB) has four 64 KiB holes, range 1 ([2, 4) MiB)
        // one of 1 MiB. With a budget of four, the 1 MiB hole and the first
        // three 64 KiB ones are remapped, though range 0 comes first.
        let small = [128 * kib, 384 * kib, 640 * kib, 896 * kib];
        let mut holes: Vec<_> = small.iter().map(|&off| (off, 64 * kib)).collect();
        holes.push((2 * MIB + 512 * kib, MIB));
        let Some(file) = file_with_holes(4 * MIB, &holes) else {
            return;
        };
        let gm = GuestMemory::from_ranges(&[(GuestAddress(0), (4 * MIB) as usize)]).unwrap();
        let mut table = MemoryRangeTable::default();
        for gpa in [0, 2 * MIB] {
            table.push(MemoryRange {
                gpa,
                length: 2 * MIB,
            });
        }
        let limits = HoleRemapLimits {
            max_holes: 4,
            ..Default::default()
        };
        let reports = do_mmap_cow_saved_regions_with(&gm, &file, &table, false, limits).unwrap();
        assert_eq!(
            reports,
            vec![
                HoleRemapReport {
                    extents: 5,
                    found: 4,
                    skipped_cap: 1,
                    holes: 3,
                    bytes: 3 * 64 * kib,
                    ..Default::default()
                },
                HoleRemapReport {
                    extents: 2,
                    found: 1,
                    holes: 1,
                    bytes: MIB,
                    ..Default::default()
                },
            ]
        );
        for report in &reports {
            assert_holes_add_up(report);
        }
        for &gpa in &small[..3] {
            assert!(!gpa_is_file_backed(&gm, gpa));
        }
        assert!(gpa_is_file_backed(&gm, small[3]));
        assert!(!gpa_is_file_backed(&gm, 2 * MIB + 512 * kib));
        assert!(gpa_is_file_backed(&gm, 3 * MIB + 512 * kib));
        for (gpa, byte) in [
            (0, 0x77),
            (small[0], 0),
            (small[3], 0),
            (2 * MIB + 512 * kib, 0),
            (4 * MIB - 1, 0x77),
        ] {
            assert_eq!(gm.read_obj::<u8>(GuestAddress(gpa)).unwrap(), byte);
        }
    }

    fn hole(range: usize, off: u64, len: u64) -> CowHole {
        CowHole { range, off, len }
    }

    // Offers `holes` in turn to a chooser of `max_holes`; returns the holes
    // it chose and those it dropped, both by range then offset.
    fn choose(holes: &[CowHole], max_holes: usize) -> (Vec<CowHole>, Vec<CowHole>) {
        let mut chooser = HoleChooser::new(max_holes);
        let mut dropped: Vec<_> = holes.iter().filter_map(|&h| chooser.offer(h)).collect();
        dropped.sort_unstable_by_key(|h| (h.range, h.off));
        (chooser.into_chosen(), dropped)
    }

    #[test]
    fn cow_hole_chooser_prefers_largest() {
        let kib = 1 << 10;
        let holes = [
            hole(0, 100 * kib, 64 * kib),
            hole(0, 400 * kib, 128 * kib),
            hole(0, 600 * kib, 64 * kib),
            hole(0, 800 * kib, 2 * MIB),
            hole(1, 0, 64 * kib),
            hole(1, 100 * kib, 4 * MIB),
        ];

        // Up to the cap, exactly at it included, every hole is chosen.
        for max_holes in [6, 7, COW_HOLE_REMAP_MAX_HOLES] {
            assert_eq!(choose(&holes, max_holes), (holes.to_vec(), Vec::new()));
        }

        // Over the cap: the largest across ranges, the earlier (by range,
        // then offset) of equal sizes, in whatever order they come.
        let chosen = vec![holes[0], holes[1], holes[3], holes[5]];
        let dropped = vec![holes[2], holes[4]];
        assert_eq!(choose(&holes, 4), (chosen.clone(), dropped.clone()));
        let mut reversed = holes;
        reversed.reverse();
        assert_eq!(choose(&reversed, 4), (chosen, dropped));

        assert_eq!(choose(&holes, 0), (Vec::new(), holes.to_vec()));
        assert_eq!(choose(&[], 4), (Vec::new(), Vec::new()));
    }

    #[test]
    fn cow_hole_chooser_drops_the_holes_of_a_failed_walk() {
        let kib = 1 << 10;
        let limits = HoleRemapLimits {
            min_size: 64 * kib,
            max_holes: 3,
        };
        let mut chooser = HoleChooser::new(limits.max_holes);
        let mut reports: Vec<_> = (0..3).map(|_| HoleRemapReport::default()).collect();
        let walk = |holes: Vec<CowHole>, result: io::Result<usize>| {
            move |on_hole: &mut dyn FnMut(u64, u64)| {
                for h in holes {
                    on_hole(h.off, h.len);
                }
                result
            }
        };

        let kept = vec![hole(0, 0, 64 * kib), hole(0, MIB, 128 * kib)];
        offer_range_holes(
            &mut chooser,
            &mut reports,
            0,
            limits,
            walk(kept.clone(), Ok(2)),
        );

        // Range 1's walk fails after finding holes larger than all those
        // kept, enough to push them over the cap: none of its holes is
        // chosen, and none of range 0's is dropped for them.
        let failed = (0..4).map(|i| hole(1, (2 + i) * MIB, 512 * kib)).collect();
        let err = io::Error::other("walk failed");
        offer_range_holes(
            &mut chooser,
            &mut reports,
            1,
            limits,
            walk(failed, Err(err)),
        );

        // Range 2's walk succeeds: its holes compete with those kept.
        let big = hole(2, 8 * MIB, MIB);
        let small = hole(2, 10 * MIB, 64 * kib);
        offer_range_holes(
            &mut chooser,
            &mut reports,
            2,
            limits,
            walk(vec![big, small], Ok(1)),
        );

        assert_eq!(chooser.into_chosen(), vec![kept[0], kept[1], big]);
        assert_eq!(
            reports,
            vec![
                HoleRemapReport {
                    extents: 2,
                    found: 2,
                    ..Default::default()
                },
                HoleRemapReport {
                    fallback: Some("seek_hole_unsupported"),
                    ..Default::default()
                },
                HoleRemapReport {
                    extents: 1,
                    found: 2,
                    skipped_cap: 1,
                    ..Default::default()
                },
            ]
        );
    }

    #[test]
    fn cow_hole_chooser_covers_a_golden_image() {
        // A memory file the size of a golden image's, about 3554 data
        // extents with a 64 KiB to 1 MiB hole after each, is covered whole.
        let kib = 1 << 10;
        let holes: Vec<_> = (0..3554u64)
            .map(|i| hole(0, i * 2 * MIB, (64 + (i % 16) * 64) * kib))
            .collect();
        assert_eq!(
            choose(&holes, COW_HOLE_REMAP_MAX_HOLES),
            (holes, Vec::new())
        );
    }

    #[test]
    fn cow_hole_remap_takes_exactly_max_holes() {
        let Some(file) = sparse_snapshot_file() else {
            return;
        };
        // Three holes over 10 MiB, with a budget of three.
        let gm = private_file_mapping(&file, 10 * MIB);
        let limits = HoleRemapLimits {
            max_holes: 3,
            ..Default::default()
        };
        let report = remap_holes(&gm, &file, limits);
        assert_eq!((report.found, report.holes, report.skipped_cap), (3, 3, 0));
        assert_eq!(report.bytes, 6 * MIB);
        assert_holes_add_up(&report);
        for gpa in [2 * MIB, 6 * MIB, 8 * MIB] {
            assert!(!gpa_is_file_backed(&gm, gpa));
        }
    }

    #[test]
    fn cow_hole_remap_handles_a_range_without_holes() {
        // Range 0 ([0, 2) MiB) is all data; range 1 ([2, 4) MiB) has a hole.
        let Some(file) = file_with_holes(4 * MIB, &[(2 * MIB + 512 * (1 << 10), MIB)]) else {
            return;
        };
        let gm = GuestMemory::from_ranges(&[(GuestAddress(0), (4 * MIB) as usize)]).unwrap();
        let mut table = MemoryRangeTable::default();
        for gpa in [0, 2 * MIB] {
            table.push(MemoryRange {
                gpa,
                length: 2 * MIB,
            });
        }
        let reports =
            do_mmap_cow_saved_regions_with(&gm, &file, &table, false, HoleRemapLimits::default())
                .unwrap();
        assert_eq!(
            reports,
            vec![
                HoleRemapReport {
                    extents: 1,
                    ..Default::default()
                },
                HoleRemapReport {
                    extents: 2,
                    found: 1,
                    holes: 1,
                    bytes: MIB,
                    ..Default::default()
                },
            ]
        );
        for report in &reports {
            assert_holes_add_up(report);
        }
        assert!(gpa_is_file_backed(&gm, 0));
        assert!(gpa_is_file_backed(&gm, 2 * MIB - 1));
        assert!(!gpa_is_file_backed(&gm, 2 * MIB + 512 * (1 << 10)));
        assert_eq!(gm.read_obj::<u8>(GuestAddress(MIB)).unwrap(), 0x77);
    }

    #[test]
    fn cow_hole_report_sums_ranges() {
        let mut total = HoleRemapReport::default();
        total.add(&HoleRemapReport {
            extents: 2,
            found: 3,
            skipped_small: 1,
            holes: 2,
            bytes: MIB,
            ..Default::default()
        });
        total.add(&HoleRemapReport {
            extents: 1,
            found: 4,
            skipped_cap: 1,
            skipped_failed: 2,
            holes: 1,
            bytes: 2 * MIB,
            fallback: Some("mmap_failed"),
            ..Default::default()
        });
        total.add(&HoleRemapReport {
            fallback: Some("unaligned"),
            ..Default::default()
        });
        assert_eq!(
            total,
            HoleRemapReport {
                extents: 3,
                found: 7,
                skipped_small: 1,
                skipped_cap: 1,
                skipped_failed: 2,
                holes: 3,
                bytes: 3 * MIB,
                fallback: Some("mmap_failed"),
            }
        );
        assert_holes_add_up(&total);
        assert_eq!(
            total.to_string(),
            "extents=3 holes_found=7 holes_remapped=3 bytes_remapped=3145728 \
             skipped_small=1 skipped_cap=1 skipped_failed=2 fallback=mmap_failed"
        );
    }

    #[test]
    fn cow_hole_remap_keeps_mapping_without_seek_hole() {
        let Some(file) = sparse_snapshot_file() else {
            return;
        };
        let gm = private_file_mapping(&file, 8 * MIB);
        // A pipe cannot seek, so its walk fails as on a filesystem without
        // SEEK_HOLE.
        let mut fds = [0; 2];
        // SAFETY: fds has room for the two descriptors pipe writes.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: pipe just returned these descriptors, owned by nothing else.
        let (pipe_rd, _pipe_wr) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
        let report = remap_holes(&gm, &pipe_rd, HoleRemapLimits::default());
        assert_eq!(report.fallback, Some("seek_hole_unsupported"));
        assert_eq!((report.holes, report.bytes), (0, 0));
        assert!(gpa_is_file_backed(&gm, 2 * MIB));
        assert_eq!(gm.read_obj::<u8>(GuestAddress(5 * MIB)).unwrap(), 0xcd);
    }

    #[test]
    fn copy_on_access_segments_follow_served_pages() {
        let page = get_page_size();
        // Two UFFD ranges with a gap between them, the second one restored
        // from further into the snapshot.
        let ranges = [
            UffdRange {
                host_addr: 0x10_0000,
                length: 4 * page,
                source_offset: 0,
                page_size: page,
            },
            UffdRange {
                host_addr: 0x10_0000 + 6 * page,
                length: 2 * page,
                source_offset: 4 * page,
                page_size: page,
            },
        ];
        let served: Arc<[AtomicBitmap]> = new_served_bitmap(&ranges).into();
        served[0].set_bit(1);
        served[0].set_bit(2);
        let pages = CopyOnAccessPages {
            source: tempfile::tempfile().unwrap(),
            ranges: Box::new(ranges),
            served,
            serve_lock: Arc::new(Mutex::new(())),
        };
        // Every segment of the window, as the snapshot writer walks it.
        let segments = |host_addr: u64, len: u64, present: &dyn Fn(u64) -> bool| {
            let mut out = Vec::new();
            let mut done = 0;
            while done < len {
                let segment = pages.next_segment(host_addr + done, len - done, &present);
                let end = segment.end();
                out.push(match segment {
                    CopyOnAccessSegment::Guest { offset, len } => CopyOnAccessSegment::Guest {
                        offset: done + offset,
                        len,
                    },
                    CopyOnAccessSegment::Source {
                        offset,
                        len,
                        source_offset,
                    } => CopyOnAccessSegment::Source {
                        offset: done + offset,
                        len,
                        source_offset,
                    },
                });
                done += end;
            }
            out
        };
        let absent = |_: u64| false;

        // From one page before the first range to one page after the last.
        let start = 0x10_0000 - page;
        assert_eq!(
            segments(start, 10 * page, &absent),
            vec![
                CopyOnAccessSegment::Guest {
                    offset: 0,
                    len: page,
                },
                CopyOnAccessSegment::Source {
                    offset: page,
                    len: page,
                    source_offset: 0,
                },
                CopyOnAccessSegment::Guest {
                    offset: 2 * page,
                    len: 2 * page,
                },
                // The last page of the first range, not merged with the
                // second range: their source offsets are not contiguous.
                CopyOnAccessSegment::Source {
                    offset: 4 * page,
                    len: page,
                    source_offset: 3 * page,
                },
                CopyOnAccessSegment::Guest {
                    offset: 5 * page,
                    len: 2 * page,
                },
                CopyOnAccessSegment::Source {
                    offset: 7 * page,
                    len: 2 * page,
                    source_offset: 4 * page,
                },
                CopyOnAccessSegment::Guest {
                    offset: 9 * page,
                    len: page,
                },
            ]
        );

        // A page never served but present is in guest memory.
        let page3 = 0x10_0000 + 3 * page;
        assert_eq!(
            segments(start, 10 * page, &|addr| addr == page3),
            vec![
                CopyOnAccessSegment::Guest {
                    offset: 0,
                    len: page,
                },
                CopyOnAccessSegment::Source {
                    offset: page,
                    len: page,
                    source_offset: 0,
                },
                CopyOnAccessSegment::Guest {
                    offset: 2 * page,
                    len: 5 * page,
                },
                CopyOnAccessSegment::Source {
                    offset: 7 * page,
                    len: 2 * page,
                    source_offset: 4 * page,
                },
                CopyOnAccessSegment::Guest {
                    offset: 9 * page,
                    len: page,
                },
            ]
        );

        // A window inside one range, starting mid-page.
        assert_eq!(
            segments(0x10_0000 + page / 2, page, &absent),
            vec![
                CopyOnAccessSegment::Source {
                    offset: 0,
                    len: page / 2,
                    source_offset: page / 2,
                },
                CopyOnAccessSegment::Guest {
                    offset: page / 2,
                    len: page / 2,
                },
            ]
        );
    }

    // Guest memory of `len` bytes at 0: private anonymous, or a shared memfd
    // like `shared=on`.
    fn test_guest_memory(shared: bool, len: u64) -> GuestMemory {
        if !shared {
            return GuestMemory::from_ranges(&[(GuestAddress(0), len as usize)]).unwrap();
        }
        // SAFETY: the name is a valid NUL-terminated string.
        let fd = unsafe { libc::memfd_create(c"coa-test".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: memfd_create returned a new fd we own.
        let file = unsafe { File::from_raw_fd(fd) };
        file.set_len(len).unwrap();
        let region = MmapRegion::build(
            Some(FileOffset::new(file, 0)),
            len as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
        )
        .unwrap();
        GuestMemory::from_regions(vec![GuestRegion::from(
            vm_memory::GuestRegionMmap::new(region, GuestAddress(0)).unwrap(),
        )])
        .unwrap()
    }

    // What the balloon does to a released page: punch a hole in a shared
    // backing file, otherwise MADV_DONTNEED.
    fn release(gm: &GuestMemory, gpa: u64, len: u64) {
        let region = gm.find_region(GuestAddress(gpa)).unwrap();
        match region.file_offset() {
            Some(f_off) if region.flags() & libc::MAP_SHARED != 0 => {
                // SAFETY: punches a hole in the memfd backing this region.
                let ret = unsafe {
                    libc::fallocate64(
                        f_off.file().as_raw_fd(),
                        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                        (f_off.start() + gpa) as libc::off64_t,
                        len as libc::off64_t,
                    )
                };
                assert_eq!(ret, 0);
            }
            _ => discard(gm, gpa, len),
        }
    }

    // A userfaultfd with all of `gm` registered for missing faults. A host
    // that does not let the test create one fails the test, unless
    // CH_TEST_SKIP_UFFD=1 says to skip it (None).
    fn register_uffd(gm: &GuestMemory) -> Option<Uffd> {
        let fd = match uffd::create(userfaultfd::UFFD_FEATURE_MISSING_SHMEM) {
            Ok(fd) => fd,
            Err(e) if env::var_os("CH_TEST_SKIP_UFFD").is_some_and(|v| v == "1") => {
                eprintln!("skipping (CH_TEST_SKIP_UFFD=1): cannot create a userfaultfd: {e}");
                return None;
            }
            Err(e) => panic!(
                "cannot create a userfaultfd: {e}; run as root or with \
                 vm.unprivileged_userfaultfd=1, or set CH_TEST_SKIP_UFFD=1 to skip"
            ),
        };
        let page = get_page_size();
        let mut ranges = Vec::new();
        let mut source_offset = 0;
        for region in gm.iter() {
            let host_addr = region.as_ptr() as u64;
            let length = region.len();
            uffd::register(fd.as_fd(), host_addr, length, false).unwrap();
            ranges.push(UffdRange {
                host_addr,
                length,
                source_offset,
                page_size: page,
            });
            source_offset += length;
        }
        Some(Uffd::new(fd, ranges.into(), Box::new([])).unwrap())
    }

    fn gpa_present(gm: &GuestMemory, gpa: u64) -> bool {
        uffd::page_present(gm.get_host_address(GuestAddress(gpa)).unwrap() as u64).unwrap()
    }

    // Whether the page at `gpa` is mapped by this mapping alone
    // (PM_MMAP_EXCLUSIVE). The zero page every process shares never is.
    fn gpa_exclusive(gm: &GuestMemory, gpa: u64) -> bool {
        use std::os::unix::fs::FileExt;

        let addr = gm.get_host_address(GuestAddress(gpa)).unwrap() as u64;
        let mut entry = [0u8; 8];
        File::open("/proc/self/pagemap")
            .unwrap()
            .read_exact_at(&mut entry, addr / get_page_size() * 8)
            .unwrap();
        u64::from_ne_bytes(entry) & (1 << 56) != 0
    }

    // A UFFD handler serving `file` into `gm` without background fill, as a
    // copy-on-access restore runs it when `private_zeroes`.
    struct TestHandler {
        stop: EventFd,
        _exit: EventFd,
        registry: Arc<UffdRegistry>,
        handle: thread::JoinHandle<Result<(), io::Error>>,
    }

    impl TestHandler {
        fn spawn(
            uffd: Uffd,
            file: File,
            served: Arc<[AtomicBitmap]>,
            private_zeroes: bool,
        ) -> Self {
            Self::spawn_with(
                uffd,
                Box::new(FileUffdMemorySource::new(file)),
                served,
                Arc::new(Mutex::new(())),
                private_zeroes,
            )
        }

        fn spawn_with(
            uffd: Uffd,
            source: Box<dyn UffdMemorySource>,
            served: Arc<[AtomicBitmap]>,
            serve_lock: Arc<Mutex<()>>,
            private_zeroes: bool,
        ) -> Self {
            let stop = EventFd::new(libc::EFD_NONBLOCK).unwrap();
            let exit = EventFd::new(libc::EFD_NONBLOCK).unwrap();
            let registry = Arc::new(UffdRegistry {
                ranges: uffd.ranges().into(),
                added_uffds: Mutex::new(vec![(VMM_UFFD_ID.to_string(), uffd)]),
                added_uffd_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                done: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            });
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let (thread_stop, thread_exit) = (stop.try_clone().unwrap(), exit.try_clone().unwrap());
            let thread_registry = Arc::clone(&registry);
            let handle = thread::spawn(move || {
                MemoryManager::uffd_handler_loop(
                    &thread_registry,
                    &thread_stop,
                    &thread_exit,
                    source,
                    served,
                    &serve_lock,
                    &ready_tx,
                    false,
                    private_zeroes,
                )
            });
            ready_rx.recv().unwrap();
            Self {
                stop,
                _exit: exit,
                registry,
                handle,
            }
        }

        fn stop(self) {
            assert!(!self.handle.is_finished(), "handler exited on its own");
            assert!(!self.registry.is_done());
            self.stop.write(1).unwrap();
            self.handle.join().unwrap().unwrap();
        }
    }

    #[test]
    fn copy_on_access_handler_copies_only_accessed_pages() {
        check_copy_on_access_handler(false);
    }

    #[test]
    fn copy_on_access_handler_copies_only_accessed_pages_shared() {
        check_copy_on_access_handler(true);
    }

    fn check_copy_on_access_handler(shared: bool) {
        use std::os::unix::fs::FileExt;

        let page = get_page_size();
        let gm = test_guest_memory(shared, 4 * page);
        let Some(uffd) = register_uffd(&gm) else {
            return;
        };
        let ranges: Box<[UffdRange]> = uffd.ranges().into();
        let served: Arc<[AtomicBitmap]> = new_served_bitmap(&ranges).into();
        let file = snapshot_file(&[(0xa0, page), (0xa1, page), (0xa2, page), (0xa3, page)]);
        let serve_lock = Arc::new(Mutex::new(()));
        let handler = TestHandler::spawn_with(
            uffd,
            Box::new(FileUffdMemorySource::new(file.reopen().unwrap())),
            Arc::clone(&served),
            Arc::clone(&serve_lock),
            true,
        );

        // Nothing is copied until it is accessed.
        thread::sleep(time::Duration::from_millis(100));
        for gpa in (0..4).map(|i| i * page) {
            assert!(!gpa_present(&gm, gpa));
        }
        assert_eq!(gm.read_obj::<u8>(GuestAddress(page)).unwrap(), 0xa1);
        assert!(gpa_present(&gm, page));
        // A first access gets a page of the VM's own too.
        assert!(gpa_exclusive(&gm, page));
        // The copy wakes the reader before the handler sets the served bit;
        // the handler holds `serve_lock` until it has, so taking it waits.
        drop(serve_lock.lock().unwrap());
        assert!(served[0].is_bit_set(1));
        thread::sleep(time::Duration::from_millis(100));
        for gpa in [0, 2 * page, 3 * page] {
            assert!(!gpa_present(&gm, gpa));
        }

        // A discarded page comes back as zeroes, not as the snapshot's copy.
        gm.write_obj::<u8>(0x5a, GuestAddress(page)).unwrap();
        release(&gm, page, page);
        assert!(!gpa_present(&gm, page));
        assert_eq!(gm.read_obj::<u8>(GuestAddress(page)).unwrap(), 0);
        assert!(gpa_present(&gm, page));
        // As a private copy, not the zero page every process shares.
        assert!(gpa_exclusive(&gm, page));

        // A written page keeps the guest's data.
        gm.write_obj::<u8>(0x77, GuestAddress(2 * page)).unwrap();
        assert_eq!(gm.read_obj::<u8>(GuestAddress(2 * page + 1)).unwrap(), 0xa2);

        // Saving copies the untouched pages from the restore source and
        // leaves them out of guest memory.
        let pages = CopyOnAccessPages {
            source: file.reopen().unwrap(),
            ranges,
            served: Arc::clone(&served),
            serve_lock: Arc::clone(&serve_lock),
        };
        let range = MemoryRange {
            gpa: 0,
            length: 4 * page,
        };
        // Without a pre-sized destination, served pages are read through the
        // guest mapping whatever the backing.
        let check_saved = |sparse_layout: bool| {
            let mut saved = tempfile::tempfile().unwrap();
            if sparse_layout {
                saved.set_len(4 * page).unwrap();
            }
            save_copy_on_access_range(&gm, &pages, &range, &mut saved, 0, sparse_layout).unwrap();
            let mut content = vec![0u8; (4 * page) as usize];
            saved.read_exact_at(&mut content, 0).unwrap();
            let byte = |gpa: u64| content[gpa as usize];
            assert_eq!(byte(0), 0xa0);
            assert_eq!(byte(page - 1), 0xa0);
            assert_eq!(byte(page), 0);
            assert_eq!(byte(2 * page), 0x77);
            assert_eq!(byte(2 * page + 1), 0xa2);
            assert_eq!(byte(3 * page), 0xa3);
            assert_eq!(byte(4 * page - 1), 0xa3);
            assert!(!gpa_present(&gm, 0));
            assert!(!gpa_present(&gm, 3 * page));
        };
        check_saved(true);
        check_saved(false);

        // A page released again and not touched since is saved as zeroes.
        // A shared backing file has the hole; private memory faults it back.
        release(&gm, page, page);
        check_saved(true);
        assert_eq!(gpa_present(&gm, page), !shared);
        check_saved(false);

        // A page written to the backing file without a fault is present, so
        // it is saved from guest memory even though it was never served.
        if shared {
            let region = gm.find_region(GuestAddress(0)).unwrap();
            let backing = region.file_offset().unwrap().file();
            backing.write_all_at(&[0x99], 3 * page).unwrap();
            assert!(!served[0].is_bit_set(3));
            let mut saved = tempfile::tempfile().unwrap();
            saved.set_len(4 * page).unwrap();
            save_copy_on_access_range(&gm, &pages, &range, &mut saved, 0, true).unwrap();
            let mut byte = [0u8; 2];
            saved.read_exact_at(&mut byte, 3 * page).unwrap();
            assert_eq!(byte, [0x99, 0]);
        }

        handler.stop();
    }

    // A source that waits for the test's go before resolving each page.
    struct GatedSource {
        inner: FileUffdMemorySource,
        entered: mpsc::Sender<()>,
        go: mpsc::Receiver<()>,
    }

    impl UffdMemorySource for GatedSource {
        fn resolve(
            &mut self,
            uffd_fd: BorrowedFd<'_>,
            range: &UffdRange,
            page_idx: u64,
        ) -> Result<(), io::Error> {
            self.entered.send(()).unwrap();
            self.go.recv().unwrap();
            self.inner.resolve(uffd_fd, range, page_idx)
        }

        fn requires_uffd_minor_mode(&self) -> bool {
            false
        }
    }

    // The snapshot writer must not decide where a page's content is while
    // the handler is resolving it: before the served bit is set, the page
    // would look untouched and be saved from the restore source.
    #[test]
    fn copy_on_access_save_waits_for_page_being_served() {
        use std::os::unix::fs::FileExt;

        let page = get_page_size();
        let gm = Arc::new(test_guest_memory(false, 2 * page));
        let Some(uffd) = register_uffd(&gm) else {
            return;
        };
        let ranges: Box<[UffdRange]> = uffd.ranges().into();
        let served: Arc<[AtomicBitmap]> = new_served_bitmap(&ranges).into();
        let serve_lock = Arc::new(Mutex::new(()));
        // The handler serves 0xc0/0xc1. The writer's restore source holds
        // 0xee, so a page saved from it is told apart.
        let served_file = snapshot_file(&[(0xc0, page), (0xc1, page)]);
        let restore_source = snapshot_file(&[(0xee, 2 * page)]);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel();
        let handler = TestHandler::spawn_with(
            uffd,
            Box::new(GatedSource {
                inner: FileUffdMemorySource::new(served_file.reopen().unwrap()),
                entered: entered_tx,
                go: go_rx,
            }),
            Arc::clone(&served),
            Arc::clone(&serve_lock),
            true,
        );

        // A vCPU faults on page 1 and the handler starts resolving it.
        let vcpu_gm = Arc::clone(&gm);
        let vcpu = thread::spawn(move || vcpu_gm.read_obj::<u8>(GuestAddress(page)).unwrap());
        entered_rx.recv().unwrap();

        // The writer starts meanwhile, and must wait.
        let pages = CopyOnAccessPages {
            source: restore_source.reopen().unwrap(),
            ranges,
            served: Arc::clone(&served),
            serve_lock,
        };
        let writer_gm = Arc::clone(&gm);
        let (saved_tx, saved_rx) = mpsc::channel();
        let writer = thread::spawn(move || {
            let mut saved = tempfile::tempfile().unwrap();
            saved.set_len(2 * page).unwrap();
            let range = MemoryRange {
                gpa: 0,
                length: 2 * page,
            };
            save_copy_on_access_range(&writer_gm, &pages, &range, &mut saved, 0, true).unwrap();
            saved_tx.send(()).unwrap();
            saved
        });
        thread::sleep(time::Duration::from_millis(100));
        assert!(saved_rx.try_recv().is_err(), "writer did not wait");

        go_tx.send(()).unwrap();
        assert_eq!(vcpu.join().unwrap(), 0xc1);
        let saved = writer.join().unwrap();
        let mut content = vec![0u8; (2 * page) as usize];
        saved.read_exact_at(&mut content, 0).unwrap();
        // Page 0 was never touched; page 1 is what the handler installed.
        assert_eq!(content[0], 0xee);
        assert_eq!(content[page as usize], 0xc1);
        assert!(!gpa_present(&gm, 0));

        handler.stop();
    }

    // Without `private_zeroes` (ondemand), a discarded page is resolved with
    // the zero page every process shares, which copy-on-access avoids.
    #[test]
    fn on_demand_handler_serves_discarded_pages_as_zero_page() {
        let page = get_page_size();
        let gm = GuestMemory::from_ranges(&[(GuestAddress(0), (2 * page) as usize)]).unwrap();
        let Some(uffd) = register_uffd(&gm) else {
            return;
        };
        let served: Arc<[AtomicBitmap]> = new_served_bitmap(uffd.ranges()).into();
        let file = snapshot_file(&[(0xb0, page), (0xb1, page)]);
        let handler = TestHandler::spawn(uffd, file.reopen().unwrap(), served, false);

        gm.write_obj::<u8>(0x5a, GuestAddress(0)).unwrap();
        discard(&gm, 0, page);
        assert_eq!(gm.read_obj::<u8>(GuestAddress(0)).unwrap(), 0);
        assert!(!gpa_exclusive(&gm, 0));

        handler.stop();
    }

    // A first access to a page that is a hole in the snapshot file, or holds
    // zeroes, gets a zeroed page of the VM's own, not the zero page every
    // process shares. restore_by_uffd leaves holes unserved for copy-on-access,
    // as here, so the handler reads them from the file like any other page.
    #[test]
    fn copy_on_access_handler_serves_zero_pages_privately() {
        check_copy_on_access_zero_pages(false);
    }

    #[test]
    fn copy_on_access_handler_serves_zero_pages_privately_shared() {
        check_copy_on_access_zero_pages(true);
    }

    fn check_copy_on_access_zero_pages(shared: bool) {
        let page = get_page_size();
        let gm = test_guest_memory(shared, 4 * page);
        let Some(uffd) = register_uffd(&gm) else {
            return;
        };
        let served: Arc<[AtomicBitmap]> = new_served_bitmap(uffd.ranges()).into();
        // Data, a hole, zeroes written as data, and a hole up to the end.
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![0xd0u8; page as usize]).unwrap();
        file.seek(SeekFrom::Start(2 * page)).unwrap();
        file.write_all(&vec![0u8; page as usize]).unwrap();
        file.set_len(4 * page).unwrap();
        let handler = TestHandler::spawn(uffd, file, served, true);

        assert_eq!(gm.read_obj::<u8>(GuestAddress(0)).unwrap(), 0xd0);
        for gpa in [page, 2 * page, 3 * page] {
            assert_eq!(gm.read_obj::<u8>(GuestAddress(gpa)).unwrap(), 0);
            assert!(gpa_present(&gm, gpa));
            assert!(gpa_exclusive(&gm, gpa), "page at {gpa:#x} is shared");
        }

        handler.stop();
    }
}
