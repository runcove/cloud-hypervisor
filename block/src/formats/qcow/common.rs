// Copyright © 2021 Intel Corporation
//
// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Shared helpers for QCOW2 sync and async backends.

use std::cmp::min;
use std::io;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

use vmm_sys_util::write_zeroes::{PunchHole, WriteZeroesAt};

use super::decoder::Decoder;
use super::metadata::{
    BackingRead, ClusterReadMapping, ClusterWriteMapping, DeallocAction, QcowMetadata,
};
use super::qcow_raw_file::QcowRawFile;
use crate::async_io::{AsyncIoError, AsyncIoOperation, AsyncIoResult};

/// Decompress a full QCOW2 cluster from compressed data.
///
/// Returns a `cluster_size` byte buffer with the decompressed cluster
/// content. Fails if the decoder does not produce exactly `cluster_size`
/// bytes.
pub(super) fn decompress_cluster(
    compressed: &[u8],
    cluster_size: usize,
    decoder: &dyn Decoder,
) -> io::Result<Vec<u8>> {
    let mut decompressed = vec![0u8; cluster_size];
    let n = decoder
        .decode(compressed, &mut decompressed)
        .map_err(|_| io::Error::from_raw_os_error(libc::EIO))?;
    if n != cluster_size {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(decompressed)
}

/// Applies one deallocation action to the data file and refcount table.
pub(super) fn apply_dealloc_action(
    metadata: &QcowMetadata,
    data_file: &mut QcowRawFile,
    action: &DeallocAction,
) -> io::Result<()> {
    match action {
        DeallocAction::PunchHole {
            host_offset,
            length,
        } => {
            data_file.file_mut().punch_hole(*host_offset, *length)?;
            metadata.complete_punch_hole(*host_offset);
            Ok(())
        }
        DeallocAction::WriteZeroes {
            host_offset,
            length,
        } => data_file
            .file_mut()
            .write_zeroes_at(*host_offset, *length)
            .map(|_| ()),
    }
}

/// Deallocates a byte range and returns the completion result, 0 on
/// success or a negative errno on the first failing action.
pub(super) fn deallocate_range_result(
    metadata: &QcowMetadata,
    data_file: &mut QcowRawFile,
    offset: u64,
    length: usize,
    sparse: bool,
    write_zeroes: bool,
    backing_file: Option<&dyn BackingRead>,
) -> i32 {
    let wrap_error: fn(io::Error) -> AsyncIoError = if write_zeroes {
        AsyncIoError::WriteZeroes
    } else {
        AsyncIoError::PunchHole
    };
    let result = metadata
        .deallocate_bytes(offset, length, sparse, write_zeroes, backing_file)
        .and_then(|actions| {
            let mut first_error = None;
            for action in &actions {
                if let Err(e) = apply_dealloc_action(metadata, data_file, action) {
                    first_error.get_or_insert(e);
                }
            }
            first_error.map_or(Ok(()), Err)
        })
        .map_err(wrap_error);
    match result {
        Ok(()) => 0,
        Err(AsyncIoError::PunchHole(e) | AsyncIoError::WriteZeroes(e)) => {
            -e.raw_os_error().unwrap_or(libc::EIO)
        }
        Err(_) => -libc::EIO,
    }
}

/// Writes an operation to the data file cluster by cluster, allocating
/// and copying up backing data as needed. Writes are synchronous because
/// the host offset is only known after the metadata allocation.
pub(super) fn cow_write_sync(
    address: u64,
    op: &AsyncIoOperation,
    metadata: &QcowMetadata,
    data_file: &QcowRawFile,
    backing_file: &Option<Arc<dyn BackingRead>>,
    cluster_size: u64,
) -> AsyncIoResult<()> {
    let total_len = op.total_len();
    let mut buf_offset = 0usize;

    while buf_offset < total_len {
        let curr_addr = address + buf_offset as u64;
        let intra_offset = curr_addr & (cluster_size - 1);
        let remaining_in_cluster = (cluster_size - intra_offset) as usize;
        let count = min(total_len - buf_offset, remaining_in_cluster);

        let backing_data = if let Some(backing) = backing_file
            .as_ref()
            .filter(|_| intra_offset != 0 || count < cluster_size as usize)
        {
            let cluster_begin = curr_addr - intra_offset;
            let mut data = vec![0u8; cluster_size as usize];
            backing
                .read_at(cluster_begin, &mut data)
                .map_err(AsyncIoError::WriteVectored)?;
            Some(data)
        } else {
            None
        };

        let mapping = metadata
            .map_cluster_for_write(curr_addr, backing_data)
            .map_err(AsyncIoError::WriteVectored)?;

        match mapping {
            ClusterWriteMapping::Allocated {
                offset: host_offset,
            } => {
                let mut buf = vec![0u8; count];
                op.read_bytes_at(buf_offset, &mut buf)
                    .map_err(AsyncIoError::WriteVectored)?;
                data_file
                    .file()
                    .write_all_at(&buf, host_offset)
                    .map_err(AsyncIoError::WriteVectored)?;
            }
        }
        buf_offset += count;
    }
    Ok(())
}

/// Reads cluster mappings synchronously into an owned operation, filling
/// holes, decompressing, and reading from the backing file as each
/// mapping requires.
pub(super) fn scatter_read_sync(
    mappings: Vec<ClusterReadMapping>,
    op: &mut AsyncIoOperation,
    data_file: &QcowRawFile,
    backing_file: &Option<Arc<dyn BackingRead>>,
    cluster_size: u64,
    decoder: &dyn Decoder,
) -> AsyncIoResult<()> {
    if let [ClusterReadMapping::Allocated { offset, length }] = mappings.as_slice()
        && op.is_read()
        && *length as usize == op.total_len()
    {
        // SAFETY: the iovecs come from op, which owns the destination
        // memory for the duration of this call.
        let n = unsafe { data_file.file().read_vectored_at(op.iovecs(), *offset) };
        if matches!(n, Ok(n) if n == op.total_len()) {
            return Ok(());
        }
    }

    let mut buf_offset = 0usize;
    for mapping in mappings {
        match mapping {
            ClusterReadMapping::Zero { length } => {
                op.fill_zeroes_at(buf_offset, length as usize)
                    .map_err(AsyncIoError::ReadVectored)?;
                buf_offset += length as usize;
            }
            ClusterReadMapping::Allocated {
                offset: host_offset,
                length,
            } => {
                let len = length as usize;
                let mut buf = vec![0u8; len];
                data_file
                    .file()
                    .read_exact_at(&mut buf, host_offset)
                    .map_err(AsyncIoError::ReadVectored)?;
                op.write_bytes_at(buf_offset, &buf)
                    .map_err(AsyncIoError::ReadVectored)?;
                buf_offset += len;
            }
            ClusterReadMapping::Compressed {
                host_offset,
                compressed_size,
                cluster_offset,
                length,
            } => {
                let mut compressed = vec![0u8; compressed_size];
                data_file
                    .file()
                    .read_exact_at(&mut compressed, host_offset)
                    .map_err(AsyncIoError::ReadVectored)?;
                let decompressed = decompress_cluster(&compressed, cluster_size as usize, decoder)
                    .map_err(AsyncIoError::ReadVectored)?;
                op.write_bytes_at(
                    buf_offset,
                    &decompressed[cluster_offset..cluster_offset + length],
                )
                .map_err(AsyncIoError::ReadVectored)?;
                buf_offset += length;
            }
            ClusterReadMapping::Backing {
                offset: backing_offset,
                length,
            } => {
                let mut buf = vec![0u8; length as usize];
                backing_file
                    .as_ref()
                    .unwrap()
                    .read_at(backing_offset, &mut buf)
                    .map_err(AsyncIoError::ReadVectored)?;
                op.write_bytes_at(buf_offset, &buf)
                    .map_err(AsyncIoError::ReadVectored)?;
                buf_offset += length as usize;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileExt;

    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use vmm_sys_util::tempfile::TempFile;

    use super::super::decoder::ZlibDecoder;
    use super::super::metadata::ClusterReadMapping;
    use super::super::qcow_raw_file::QcowRawFile;
    use super::{decompress_cluster, scatter_read_sync};
    use crate::aligned_file::AlignedFile;
    use crate::async_io::{AsyncIo, AsyncIoCompletion, AsyncIoOperation, OwnedIoBuffer};
    use crate::disk_file::{AsyncDiskFile, MetadataSync};
    use crate::formats::qcow::{BackingFileConfig, ImageType, QcowDisk, QcowTempDisk};

    const COMPRESSED_FLAG: u64 = 1 << 62;
    const CLUSTER_USED_FLAG: u64 = 1 << 63;
    const COMPRESSED_SECTOR_SIZE: u64 = 512;

    const HEADER_CLUSTER_BITS_OFFSET: u64 = 20;
    const HEADER_L1_SIZE_OFFSET: u64 = 36;
    const HEADER_L1_TABLE_OFFSET: u64 = 40;

    const L1_L2_ADDR_MASK: u64 = 0x00ff_ffff_ffff_fe00;

    fn make_compressed_l2_entry(host_offset: u64, compressed_len: usize, cluster_bits: u32) -> u64 {
        let compressed_size_shift = 62 - (cluster_bits - 8);
        let intra_sector_offset = host_offset & (COMPRESSED_SECTOR_SIZE - 1);
        let total_bytes = compressed_len as u64 + intra_sector_offset;
        let nsectors = total_bytes.div_ceil(COMPRESSED_SECTOR_SIZE);
        let addr_part = host_offset & ((1 << compressed_size_shift) - 1);
        let size_part = (nsectors - 1) << compressed_size_shift;
        COMPRESSED_FLAG | size_part | addr_part
    }

    const WZ_CLUSTER: u64 = 1 << 16;
    const WZ_DISK_SIZE: u64 = 6 * WZ_CLUSTER;
    const WZ_BACKING_BYTE: u8 = 0xAB;
    const WZ_OVERLAY_BYTE: u8 = 0xCD;

    /// `(offset, length)` of one whole cluster.
    pub(crate) const WZ_WHOLE_CLUSTER: (u64, u64) = (WZ_CLUSTER, WZ_CLUSTER);
    /// The end of one cluster, a whole cluster and the start of the next.
    pub(crate) const WZ_ACROSS_BOUNDARY: (u64, u64) = (WZ_CLUSTER + WZ_CLUSTER / 2, 2 * WZ_CLUSTER);
    /// The end of one cluster and the start of the next, nothing whole.
    pub(crate) const WZ_PARTIAL_ACROSS_BOUNDARY: (u64, u64) = (2 * WZ_CLUSTER - 4096, 8192);
    /// A range inside one cluster.
    pub(crate) const WZ_PARTIAL_INSIDE_CLUSTER: (u64, u64) = (WZ_CLUSTER + 4096, 4096);

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

    /// Runs a write zeroes with UNMAP on `(offset, length)` with and without
    /// a backing file, sparse on and off, on allocated and unallocated
    /// clusters, and checks what reads back, before and after a reopen, and
    /// that whole clusters are deallocated when sparse is on.
    pub(crate) fn check_write_zeroes_unmap(use_io_uring: bool, (offset, length): (u64, u64)) {
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

    /// A discard is only a hint: with sparse on, its whole clusters still read
    /// from the backing file, while its partial ones are zeroed in the overlay.
    pub(crate) fn check_discard_uncovers_backing(use_io_uring: bool) {
        let (offset, length) = WZ_ACROSS_BOUNDARY;
        let whole = (2 * WZ_CLUSTER) as usize..(3 * WZ_CLUSTER) as usize;

        for allocated in [true, false] {
            let (disk, mut expected, _backing, _overlay) =
                wz_disk(true, allocated, true, use_io_uring);
            let mut async_io = disk.create_async_io(1).unwrap();
            async_io.punch_hole(offset, length, 7).unwrap();
            assert_eq!(wz_wait(async_io.as_mut()).result, 0);
            drop(async_io);

            expected[offset as usize..(offset + length) as usize].fill(0);
            expected[whole.clone()].fill(WZ_BACKING_BYTE);
            assert_eq!(
                wz_difference(&wz_read_all(&disk), &expected),
                None,
                "allocated={allocated}"
            );
        }
    }

    /// Compress every allocated cluster in a QCOW2 image file in place.
    pub(crate) fn compress_allocated_clusters(file: &mut File) {
        let mut buf4 = [0u8; 4];
        file.read_exact_at(&mut buf4, HEADER_CLUSTER_BITS_OFFSET)
            .unwrap();
        let cluster_bits = u32::from_be_bytes(buf4);
        let cluster_size = 1u64 << cluster_bits;

        file.read_exact_at(&mut buf4, HEADER_L1_SIZE_OFFSET)
            .unwrap();
        let l1_size = u32::from_be_bytes(buf4);

        let mut buf8 = [0u8; 8];
        file.read_exact_at(&mut buf8, HEADER_L1_TABLE_OFFSET)
            .unwrap();
        let l1_table_offset = u64::from_be_bytes(buf8);

        let entries_per_l2 = cluster_size / 8;

        let mut append_offset = file.metadata().unwrap().len();
        append_offset = (append_offset + 511) & !511;

        for l1_idx in 0..l1_size as u64 {
            let l1_entry_offset = l1_table_offset + l1_idx * 8;
            file.read_exact_at(&mut buf8, l1_entry_offset).unwrap();
            let l1_entry = u64::from_be_bytes(buf8);

            let l2_table_addr = l1_entry & L1_L2_ADDR_MASK;
            if l2_table_addr == 0 {
                continue;
            }

            for l2_idx in 0..entries_per_l2 {
                let l2_entry_offset = l2_table_addr + l2_idx * 8;
                file.read_exact_at(&mut buf8, l2_entry_offset).unwrap();
                let l2_entry = u64::from_be_bytes(buf8);

                if l2_entry & CLUSTER_USED_FLAG == 0 || l2_entry & COMPRESSED_FLAG != 0 {
                    continue;
                }

                let host_cluster_addr = l2_entry & L1_L2_ADDR_MASK;
                if host_cluster_addr == 0 {
                    continue;
                }

                let mut cluster_data = vec![0u8; cluster_size as usize];
                file.read_exact_at(&mut cluster_data, host_cluster_addr)
                    .unwrap();

                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&cluster_data).unwrap();
                let compressed = encoder.finish().unwrap();

                file.write_all_at(&compressed, append_offset).unwrap();

                let padded_len = (compressed.len() + 511) & !511;
                if padded_len > compressed.len() {
                    let padding = vec![0u8; padded_len - compressed.len()];
                    file.write_all_at(&padding, append_offset + compressed.len() as u64)
                        .unwrap();
                }

                let new_entry =
                    make_compressed_l2_entry(append_offset, compressed.len(), cluster_bits);
                file.write_all_at(&new_entry.to_be_bytes(), l2_entry_offset)
                    .unwrap();

                append_offset += padded_len as u64;
            }
        }

        file.flush().unwrap();
    }

    #[test]
    fn test_decompress_cluster() {
        let cluster_size = 65536;
        let original: Vec<u8> = (0..=255).cycle().take(cluster_size).collect();

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress_cluster(&compressed, cluster_size, &ZlibDecoder {}).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_decompress_cluster_corrupt_input() {
        let corrupt = vec![0xffu8; 64];
        let err = decompress_cluster(&corrupt, 65536, &ZlibDecoder {}).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn single_full_mapping_short_read_errors() {
        // The mapping claims 200 bytes but the file holds only 100.
        let src: Vec<u8> = (0..100u8).collect();
        let tmp = TempFile::new().unwrap();
        tmp.as_file().write_all(&src).unwrap();
        tmp.as_file().sync_all().unwrap();

        let aligned = AlignedFile::new(tmp.as_file().try_clone().unwrap(), false);
        let data_file = QcowRawFile::from(aligned, 65536, 16).unwrap();

        let mut op = AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0u8; 200]), 1);
        let mappings = vec![ClusterReadMapping::Allocated {
            offset: 0,
            length: 200,
        }];

        assert!(
            scatter_read_sync(mappings, &mut op, &data_file, &None, 65536, &ZlibDecoder {})
                .is_err()
        );
    }

    #[test]
    fn single_full_mapping_reads_fast_path() {
        let cluster = 65536usize;
        let src: Vec<u8> = (0..cluster).map(|i| (i % 251) as u8).collect();
        let tmp = TempFile::new().unwrap();
        tmp.as_file().write_all(&src).unwrap();
        tmp.as_file().sync_all().unwrap();

        let aligned = AlignedFile::new(tmp.as_file().try_clone().unwrap(), false);
        let data_file = QcowRawFile::from(aligned, cluster as u64, 16).unwrap();

        let mut op =
            AsyncIoOperation::read_to_vec(0, OwnedIoBuffer::from_vec(vec![0u8; cluster]), 1);
        let mappings = vec![ClusterReadMapping::Allocated {
            offset: 0,
            length: cluster as u64,
        }];

        scatter_read_sync(
            mappings,
            &mut op,
            &data_file,
            &None,
            cluster as u64,
            &ZlibDecoder {},
        )
        .unwrap();

        let buffer = op.into_completion_buffer().unwrap();
        assert_eq!(buffer.as_slice(), src.as_slice());
    }
}
