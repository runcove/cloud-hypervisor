// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests of how qcow2 write zeroes and discard read back: over a
//! backing file, through a chain, on version 2 images, and across repeated
//! zero and write cycles. Each runs on the sync engine and, with the
//! `io_uring` feature, on the io_uring engine.

use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::process::Command;

use vmm_sys_util::tempfile::TempFile;

use super::metadata::QcowMetadata;
use super::parser::parse_qcow;
use super::test_util::{header_field, read_u64_at};
use super::util::{COMPRESSED_FLAG, L1_TABLE_OFFSET_MASK, MAX_NESTING_DEPTH, ZERO_FLAG};
use super::{BackingFileConfig, ImageType, QcowDisk, QcowHeader, QcowTempDisk};
use crate::aligned_file::AlignedFile;
use crate::async_io::{AsyncIo, AsyncIoCompletion, OwnedIoBuffer};
use crate::disk_file::{AsyncDiskFile, MetadataSync};

const WZ_CLUSTER: u64 = 1 << 16;
const WZ_DISK_SIZE: u64 = 6 * WZ_CLUSTER;
const WZ_BACKING_BYTE: u8 = 0xAB;
const WZ_OVERLAY_BYTE: u8 = 0xCD;

/// `(offset, length)` of one whole cluster.
const WZ_WHOLE_CLUSTER: (u64, u64) = (WZ_CLUSTER, WZ_CLUSTER);
/// The end of one cluster, a whole cluster and the start of the next.
const WZ_ACROSS_BOUNDARY: (u64, u64) = (WZ_CLUSTER + WZ_CLUSTER / 2, 2 * WZ_CLUSTER);
/// The end of one cluster and the start of the next, nothing whole.
const WZ_PARTIAL_ACROSS_BOUNDARY: (u64, u64) = (2 * WZ_CLUSTER - 4096, 8192);
/// A range inside one cluster.
const WZ_PARTIAL_INSIDE_CLUSTER: (u64, u64) = (WZ_CLUSTER + 4096, 4096);

fn wz_wait(async_io: &mut dyn AsyncIo) -> AsyncIoCompletion {
    loop {
        if let Some(completion) = async_io.next_completed_request() {
            return completion;
        }
        // Only io_uring gets here: the sync engine completes on submit.
        let fd = async_io.notifier().as_raw_fd();
        let mut val = 0u64;
        // SAFETY: reading 8 bytes from a valid eventfd.
        unsafe {
            libc::read(fd, (&raw mut val).cast(), 8);
        }
    }
}

fn wz_read_all(disk: &QcowDisk) -> Vec<u8> {
    let mut async_io = disk.create_async_io(1).unwrap();
    let buffer = OwnedIoBuffer::from_vec(vec![0x5A; WZ_DISK_SIZE as usize]);
    async_io.read_to_vec(0, buffer, 1).unwrap();
    let mut completion = wz_wait(async_io.as_mut());
    assert_eq!(completion.result as u64, WZ_DISK_SIZE);
    completion.buffer.take().unwrap().as_slice().to_vec()
}

fn wz_used_clusters(file: &File, disk: &QcowDisk) -> u64 {
    let clusters = file.metadata().unwrap().len() / WZ_CLUSTER;
    (0..clusters)
        .filter(|c| disk.metadata().cluster_refcount(c * WZ_CLUSTER).unwrap() != 0)
        .count() as u64
}

/// Reports where `actual` differs from `expected`, if it does.
fn wz_difference(actual: &[u8], expected: &[u8]) -> Option<String> {
    let at = actual.iter().zip(expected).position(|(a, e)| a != e)?;
    Some(format!(
        "byte {at:#x} is {:#x}, expected {:#x}",
        actual[at], expected[at]
    ))
}

/// An image over a backing file of [`WZ_BACKING_BYTE`] if `backing`, with
/// every cluster holding [`WZ_OVERLAY_BYTE`] if `allocated`. Returns the
/// open disk, the bytes it holds and the files to keep alive.
fn wz_disk(
    backing: bool,
    allocated: bool,
    sparse: bool,
    use_io_uring: bool,
) -> (QcowDisk, Vec<u8>, TempFile, TempFile) {
    let backing_temp = TempFile::new().unwrap();
    backing_temp
        .as_file()
        .write_all(&vec![WZ_BACKING_BYTE; WZ_DISK_SIZE as usize])
        .unwrap();
    let config = BackingFileConfig {
        path: backing_temp.as_path().to_str().unwrap().to_string(),
        format: Some(ImageType::Raw),
    };
    let overlay_temp = QcowTempDisk::new(
        WZ_DISK_SIZE,
        backing.then_some(&config),
        false,
        sparse,
        false,
    )
    .unwrap()
    .into_tempfile();
    let disk = wz_open(&overlay_temp, sparse, use_io_uring);

    let mut contents = vec![if backing { WZ_BACKING_BYTE } else { 0 }; WZ_DISK_SIZE as usize];
    if allocated {
        contents.fill(WZ_OVERLAY_BYTE);
        let mut async_io = disk.create_async_io(1).unwrap();
        async_io
            .write_from_vec(0, OwnedIoBuffer::from_vec(contents.clone()), 1)
            .unwrap();
        assert_eq!(wz_wait(async_io.as_mut()).result as u64, WZ_DISK_SIZE);
    }
    (disk, contents, backing_temp, overlay_temp)
}

fn wz_open(overlay: &TempFile, sparse: bool, use_io_uring: bool) -> QcowDisk {
    let file = overlay.as_file().try_clone().unwrap();
    QcowDisk::new(file, false, true, sparse, use_io_uring).unwrap()
}

/// Writes `byte` over the clusters `first..first + count` of `disk`.
fn wz_fill_clusters(disk: &QcowDisk, first: u64, count: u64, byte: u8) {
    let mut async_io = disk.create_async_io(1).unwrap();
    let length = count * WZ_CLUSTER;
    let buffer = OwnedIoBuffer::from_vec(vec![byte; length as usize]);
    async_io
        .write_from_vec((first * WZ_CLUSTER) as libc::off_t, buffer, 1)
        .unwrap();
    assert_eq!(wz_wait(async_io.as_mut()).result as u64, length);
}

/// Runs a write zeroes with UNMAP on `(offset, length)` with and without
/// a backing file, sparse on and off, on allocated and unallocated
/// clusters, and checks what reads back, before and after a reopen, and
/// that whole clusters are deallocated when sparse is on.
fn check_write_zeroes_unmap(use_io_uring: bool, (offset, length): (u64, u64)) {
    let (start, end) = (offset as usize, (offset + length) as usize);
    let whole_clusters =
        ((offset + length) / WZ_CLUSTER).saturating_sub(offset.div_ceil(WZ_CLUSTER));
    let mut failures = Vec::new();

    for backing in [true, false] {
        for sparse in [true, false] {
            for allocated in [true, false] {
                let (disk, mut expected, _backing, overlay) =
                    wz_disk(backing, allocated, sparse, use_io_uring);
                let case = format!("backing={backing} sparse={sparse} allocated={allocated}");
                let used_before = wz_used_clusters(overlay.as_file(), &disk);

                let mut async_io = disk.create_async_io(1).unwrap();
                async_io.write_zeroes_unmap(offset, length, 7).unwrap();
                assert_eq!(wz_wait(async_io.as_mut()).result, 0, "{case}");
                drop(async_io);

                expected[start..end].fill(0);
                if let Some(difference) = wz_difference(&wz_read_all(&disk), &expected) {
                    failures.push(format!("{case}: {difference}"));
                }

                if allocated {
                    let freed = if sparse { whole_clusters } else { 0 };
                    let used_after = wz_used_clusters(overlay.as_file(), &disk);
                    assert_eq!(used_before - used_after, freed, "{case}");
                }

                disk.sync_metadata().unwrap();
                let reopened = wz_open(&overlay, sparse, use_io_uring);
                if let Some(difference) = wz_difference(&wz_read_all(&reopened), &expected) {
                    failures.push(format!("{case} after reopen: {difference}"));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "write zeroes with UNMAP at {offset:#x}+{length:#x} did not read back zeroes:\n{}",
        failures.join("\n")
    );
}

/// A write zeroes with UNMAP through the top of a chain three levels deep
/// must read back as zeroes even when only the middle layer holds data
/// for the cluster, whether the base is a raw or a qcow2 file. The base
/// holds [`WZ_BACKING_BYTE`] everywhere and the middle layer holds
/// [`WZ_OVERLAY_BYTE`] in clusters 1 and 2, which the top does not
/// allocate. Zeroing cluster 1 must leave cluster 2 reading the middle
/// layer, before and after a reopen.
fn check_write_zeroes_unmap_through_chain(use_io_uring: bool) {
    let (offset, length) = WZ_WHOLE_CLUSTER;
    let mut failures = Vec::new();

    for qcow2_base in [false, true] {
        for sparse in [true, false] {
            let case = format!("qcow2_base={qcow2_base} sparse={sparse}");

            // The base.
            let base = if qcow2_base {
                let base =
                    QcowTempDisk::new(WZ_DISK_SIZE, None, false, sparse, use_io_uring).unwrap();
                wz_fill_clusters(base.disk(), 0, WZ_DISK_SIZE / WZ_CLUSTER, WZ_BACKING_BYTE);
                base.disk().sync_metadata().unwrap();
                base.into_tempfile()
            } else {
                let base = TempFile::new().unwrap();
                base.as_file()
                    .write_all(&vec![WZ_BACKING_BYTE; WZ_DISK_SIZE as usize])
                    .unwrap();
                base
            };
            let base_format = if qcow2_base {
                ImageType::Qcow2
            } else {
                ImageType::Raw
            };

            // The middle layer, with data in clusters 1 and 2.
            let middle_config = BackingFileConfig {
                path: base.as_path().to_str().unwrap().to_string(),
                format: Some(base_format),
            };
            let middle = QcowTempDisk::new(
                WZ_DISK_SIZE,
                Some(&middle_config),
                false,
                sparse,
                use_io_uring,
            )
            .unwrap();
            wz_fill_clusters(middle.disk(), 1, 2, WZ_OVERLAY_BYTE);
            middle.disk().sync_metadata().unwrap();
            let middle = middle.into_tempfile();

            // The top, which allocates nothing.
            let top_config = BackingFileConfig {
                path: middle.as_path().to_str().unwrap().to_string(),
                format: Some(ImageType::Qcow2),
            };
            let top =
                QcowTempDisk::new(WZ_DISK_SIZE, Some(&top_config), false, sparse, use_io_uring)
                    .unwrap()
                    .into_tempfile();
            let disk = wz_open(&top, sparse, use_io_uring);

            let mut expected = vec![WZ_BACKING_BYTE; WZ_DISK_SIZE as usize];
            expected[WZ_CLUSTER as usize..3 * WZ_CLUSTER as usize].fill(WZ_OVERLAY_BYTE);
            if let Some(difference) = wz_difference(&wz_read_all(&disk), &expected) {
                failures.push(format!("{case} before zeroing: {difference}"));
            }

            let mut async_io = disk.create_async_io(1).unwrap();
            async_io.write_zeroes_unmap(offset, length, 7).unwrap();
            assert_eq!(wz_wait(async_io.as_mut()).result, 0, "{case}");
            drop(async_io);

            expected[offset as usize..(offset + length) as usize].fill(0);
            if let Some(difference) = wz_difference(&wz_read_all(&disk), &expected) {
                failures.push(format!("{case}: {difference}"));
            }

            disk.sync_metadata().unwrap();
            let reopened = wz_open(&top, sparse, use_io_uring);
            if let Some(difference) = wz_difference(&wz_read_all(&reopened), &expected) {
                failures.push(format!("{case} after reopen: {difference}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "write zeroes with UNMAP through a three level chain did not read back as expected:\n{}",
        failures.join("\n")
    );
}

/// A discard over a backing file reads back as zeroes, its whole clusters as
/// well as its partial ones, as upstream decided in 8740d147d: the whole
/// clusters get a zero entry rather than uncovering the backing file.
fn check_discard_over_backing_reads_zero(use_io_uring: bool) {
    let (offset, length) = WZ_ACROSS_BOUNDARY;

    for allocated in [true, false] {
        let (disk, mut expected, _backing, _overlay) = wz_disk(true, allocated, true, use_io_uring);
        let mut async_io = disk.create_async_io(1).unwrap();
        async_io.punch_hole(offset, length, 7).unwrap();
        assert_eq!(wz_wait(async_io.as_mut()).result, 0);
        drop(async_io);

        expected[offset as usize..(offset + length) as usize].fill(0);
        assert_eq!(
            wz_difference(&wz_read_all(&disk), &expected),
            None,
            "allocated={allocated}"
        );
    }
}

/// A version 2 image over a backing file of [`WZ_BACKING_BYTE`] if
/// `backing`, with every cluster holding [`WZ_OVERLAY_BYTE`] if `allocated`.
/// Returns the same as [`wz_disk`].
fn wz_v2_disk(
    backing: bool,
    allocated: bool,
    sparse: bool,
    use_io_uring: bool,
) -> (QcowDisk, Vec<u8>, TempFile, TempFile) {
    let backing_temp = TempFile::new().unwrap();
    backing_temp
        .as_file()
        .write_all(&vec![WZ_BACKING_BYTE; WZ_DISK_SIZE as usize])
        .unwrap();
    let path = backing_temp.as_path().to_str().unwrap();

    let overlay_temp = TempFile::new().unwrap();
    let header =
        QcowHeader::create_for_size_and_path(2, WZ_DISK_SIZE, backing.then_some(path)).unwrap();
    let raw = AlignedFile::new(overlay_temp.as_file().try_clone().unwrap(), false);
    header.write_to(&raw).unwrap();
    let (inner, _backing, _sparse) = parse_qcow(raw, MAX_NESTING_DEPTH, true).unwrap();
    QcowMetadata::new(inner).shutdown();

    let disk = wz_open(&overlay_temp, sparse, use_io_uring);
    assert_eq!(disk.metadata().header().version, 2);
    let mut contents = vec![if backing { WZ_BACKING_BYTE } else { 0 }; WZ_DISK_SIZE as usize];
    if allocated {
        wz_fill_clusters(&disk, 0, WZ_DISK_SIZE / WZ_CLUSTER, WZ_OVERLAY_BYTE);
        contents.fill(WZ_OVERLAY_BYTE);
    }
    (disk, contents, backing_temp, overlay_temp)
}

/// The L2 entries in `file` with the zero flag set.
fn wz_zero_flagged_l2_entries(file: &File) -> Vec<u64> {
    let mut l1_size = [0u8; 4];
    file.read_exact_at(&mut l1_size, header_field::L1_SIZE as u64)
        .unwrap();
    let l1_table = read_u64_at(file, header_field::L1_TABLE_OFFSET as u64);

    let mut flagged = Vec::new();
    for l1_index in 0..u64::from(u32::from_be_bytes(l1_size)) {
        let l2_table = read_u64_at(file, l1_table + l1_index * 8) & L1_TABLE_OFFSET_MASK;
        if l2_table == 0 {
            continue;
        }
        for l2_index in 0..WZ_CLUSTER / 8 {
            let l2_entry = read_u64_at(file, l2_table + l2_index * 8);
            if l2_entry & COMPRESSED_FLAG == 0 && l2_entry & ZERO_FLAG != 0 {
                flagged.push(l2_entry);
            }
        }
    }
    flagged
}

/// Asks qemu-img, when it is installed, what it makes of a closed image:
/// whether `qemu-img check` is clean and whether it reads `expected`.
/// Returns what it objected to.
fn wz_qemu_img_objection(image: &TempFile, expected: &[u8]) -> Option<String> {
    let path = image.as_path();
    let check = match Command::new("qemu-img")
        .args(["check", "-f", "qcow2"])
        .arg(path)
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!("skipping the qemu-img comparison: qemu-img unavailable");
            return None;
        }
        Err(e) => panic!("cannot run qemu-img: {e}"),
    };
    if !check.status.success() {
        return Some(format!(
            "qemu-img check: {}{}",
            String::from_utf8_lossy(&check.stdout),
            String::from_utf8_lossy(&check.stderr)
        ));
    }

    let raw = TempFile::new().unwrap();
    let convert = Command::new("qemu-img")
        .args(["convert", "-f", "qcow2", "-O", "raw"])
        .arg(path)
        .arg(raw.as_path())
        .output()
        .unwrap();
    if !convert.status.success() {
        return Some(format!(
            "qemu-img convert: {}",
            String::from_utf8_lossy(&convert.stderr)
        ));
    }
    wz_difference(&fs::read(raw.as_path()).unwrap(), expected)
        .map(|difference| format!("qemu-img reads: {difference}"))
}

/// The zero flag only exists from version 3: qemu treats it on a version 2
/// image as corruption. A write zeroes and a discard must leave a version 2
/// image without it, read back as zeroes as they do on version 3, also over a
/// backing file, and leave an image qemu reads the same.
fn check_v2_image_gets_no_zero_flag(use_io_uring: bool) {
    // Half of cluster 1, all of cluster 2 and half of cluster 3.
    let (offset, length) = WZ_ACROSS_BOUNDARY;
    let mut failures = Vec::new();

    for backing in [true, false] {
        for sparse in [true, false] {
            for allocated in [true, false] {
                for write_zeroes in [true, false] {
                    let case = format!(
                        "backing={backing} sparse={sparse} allocated={allocated} \
                         write_zeroes={write_zeroes}"
                    );
                    let (disk, mut expected, _backing, overlay) =
                        wz_v2_disk(backing, allocated, sparse, use_io_uring);

                    let mut async_io = disk.create_async_io(1).unwrap();
                    if write_zeroes {
                        async_io.write_zeroes(offset, length, 7).unwrap();
                    } else {
                        async_io.punch_hole(offset, length, 7).unwrap();
                    }
                    assert_eq!(wz_wait(async_io.as_mut()).result, 0, "{case}");
                    drop(async_io);

                    // A discard reads back as zeroes too, over a backing
                    // file as well (upstream 8740d147d).
                    expected[offset as usize..(offset + length) as usize].fill(0);

                    if let Some(difference) = wz_difference(&wz_read_all(&disk), &expected) {
                        failures.push(format!("{case}: {difference}"));
                    }
                    disk.sync_metadata().unwrap();
                    drop(disk);

                    let flagged = wz_zero_flagged_l2_entries(overlay.as_file());
                    if !flagged.is_empty() {
                        failures.push(format!("{case}: zero flag in {flagged:#x?}"));
                    }
                    let reopened = wz_open(&overlay, sparse, use_io_uring);
                    if let Some(difference) = wz_difference(&wz_read_all(&reopened), &expected) {
                        failures.push(format!("{case} after reopen: {difference}"));
                    }
                    drop(reopened);
                    if let Some(objection) = wz_qemu_img_objection(&overlay, &expected) {
                        failures.push(format!("{case}: {objection}"));
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// With sparse off, a write zeroes keeps the host cluster in the zero
/// entry. A partial write after it must take that cluster back rather than
/// append another one and leak it, so that repeating the two does not grow
/// the file, and must still read zeroes in the rest of the cluster.
fn check_zero_then_write_cycles_do_not_grow_file(use_io_uring: bool) {
    const SETTLING_CYCLES: usize = 2;
    const MEASURED_CYCLES: usize = 16;
    let (offset, length) = WZ_WHOLE_CLUSTER;
    let written = (offset + 4096) as usize..(offset + 8192) as usize;
    let mut failures = Vec::new();

    for backing in [true, false] {
        for flush_between in [true, false] {
            let case = format!("backing={backing} flush_between={flush_between}");
            let (disk, mut expected, _backing, overlay) =
                wz_disk(backing, true, false, use_io_uring);
            disk.sync_metadata().unwrap();
            let mut async_io = disk.create_async_io(1).unwrap();
            expected[offset as usize..(offset + length) as usize].fill(0);
            expected[written.clone()].fill(WZ_OVERLAY_BYTE);

            let mut settled = None;
            for cycle in 0..SETTLING_CYCLES + MEASURED_CYCLES {
                async_io.write_zeroes(offset, length, 7).unwrap();
                assert_eq!(wz_wait(async_io.as_mut()).result, 0, "{case}");
                if flush_between {
                    disk.sync_metadata().unwrap();
                }
                let buffer = OwnedIoBuffer::from_vec(vec![WZ_OVERLAY_BYTE; written.len()]);
                async_io
                    .write_from_vec(written.start as libc::off_t, buffer, 8)
                    .unwrap();
                assert_eq!(
                    wz_wait(async_io.as_mut()).result as usize,
                    written.len(),
                    "{case}"
                );
                disk.sync_metadata().unwrap();

                if let Some(difference) = wz_difference(&wz_read_all(&disk), &expected) {
                    failures.push(format!("{case} cycle {cycle}: {difference}"));
                }
                if cycle + 1 == SETTLING_CYCLES {
                    settled = Some((
                        overlay.as_file().metadata().unwrap().len(),
                        wz_used_clusters(overlay.as_file(), &disk),
                    ));
                }
            }
            drop(async_io);

            let (settled_len, settled_used) = settled.unwrap();
            let len = overlay.as_file().metadata().unwrap().len();
            let used = wz_used_clusters(overlay.as_file(), &disk);
            if (len, used) != (settled_len, settled_used) {
                failures.push(format!(
                    "{case}: after {MEASURED_CYCLES} cycles the file went from {settled_len} \
                     to {len} bytes and from {settled_used} to {used} clusters in use"
                ));
            }
            drop(disk);

            let reopened = wz_open(&overlay, false, use_io_uring);
            if let Some(difference) = wz_difference(&wz_read_all(&reopened), &expected) {
                failures.push(format!("{case} after reopen: {difference}"));
            }
            drop(reopened);
            if let Some(objection) = wz_qemu_img_objection(&overlay, &expected) {
                failures.push(format!("{case}: {objection}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Declares one test per engine, `sync` always and `uring` with io_uring,
/// each running the given checks with `use_io_uring` as their first argument.
macro_rules! both_engines {
    ($name:ident: $($check:ident($($arg:ident),*));+ $(;)?) => {
        mod $name {
            #[test]
            fn sync() {
                let use_io_uring = false;
                $(super::$check(use_io_uring $(, super::$arg)*);)+
            }

            #[cfg(feature = "io_uring")]
            #[test]
            fn uring() {
                let use_io_uring = true;
                $(super::$check(use_io_uring $(, super::$arg)*);)+
            }
        }
    };
}

both_engines!(write_zeroes_unmap_whole_cluster_reads_zero:
    check_write_zeroes_unmap(WZ_WHOLE_CLUSTER));
both_engines!(write_zeroes_unmap_across_cluster_boundary_reads_zero:
    check_write_zeroes_unmap(WZ_ACROSS_BOUNDARY));
both_engines!(write_zeroes_unmap_partial_clusters_read_zero:
    check_write_zeroes_unmap(WZ_PARTIAL_ACROSS_BOUNDARY);
    check_write_zeroes_unmap(WZ_PARTIAL_INSIDE_CLUSTER));
both_engines!(write_zeroes_unmap_through_three_level_chain:
    check_write_zeroes_unmap_through_chain());
both_engines!(discard_over_backing_file_reads_zero:
    check_discard_over_backing_reads_zero());
both_engines!(v2_image_gets_no_zero_flag: check_v2_image_gets_no_zero_flag());
both_engines!(zero_then_write_cycles_do_not_grow_file:
    check_zero_then_write_cycles_do_not_grow_file());
