// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Shared test helpers for [`AsyncIo`] backends.
//!
//! Each helper takes a `&mut dyn AsyncIo` together with the [`File`] handle
//! that backs the I/O object, so the same logic exercises every backend with
//! only the constructor differing.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use vmm_sys_util::tempfile::TempFile;

use crate::async_io::{AsyncIo, AsyncIoCompletion, BlockingOp, OwnedIoBuffer};
use crate::sparse::{write_zeroes, write_zeroes_unmap};

fn next_completion(async_io: &mut dyn AsyncIo) -> (u64, i32) {
    let completion = async_io.next_completed_request().expect("No completion");
    (completion.user_data, completion.result)
}

/// Tests punching a hole in the middle of a 4 MB file and verifying data
/// integrity around the hole.
pub(crate) fn test_punch_hole(async_io: &mut dyn AsyncIo, file: &mut File) {
    // Write 4MB of data
    let data = vec![0xAA; 4 * 1024 * 1024];
    file.write_all(&data).unwrap();
    file.sync_all().unwrap();

    // Punch hole in the middle (1MB at offset 1MB)
    let offset = 1024 * 1024;
    let length = 1024 * 1024;
    async_io.punch_hole(offset, length, 1).unwrap();

    // Check completion
    let (user_data, result) = next_completion(async_io);
    assert_eq!(user_data, 1);
    assert_eq!(result, 0);

    // Verify the hole reads as zeros
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut read_buf = vec![0; length as usize];
    file.read_exact(&mut read_buf).unwrap();
    assert!(
        read_buf.iter().all(|&b| b == 0),
        "Punched hole should read as zeros"
    );

    // Verify data before hole is intact
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut read_buf = vec![0; 1024];
    file.read_exact(&mut read_buf).unwrap();
    assert!(
        read_buf.iter().all(|&b| b == 0xAA),
        "Data before hole should be intact"
    );

    // Verify data after hole is intact
    file.seek(SeekFrom::Start(offset + length)).unwrap();
    let mut read_buf = vec![0; 1024];
    file.read_exact(&mut read_buf).unwrap();
    assert!(
        read_buf.iter().all(|&b| b == 0xAA),
        "Data after hole should be intact"
    );
}

/// Tests writing zeroes to a 512 KB region inside a 4 MB file and verifying
/// surrounding data is preserved.
pub(crate) fn test_write_zeroes(async_io: &mut dyn AsyncIo, file: &mut File) {
    // Write 4MB of data
    let data = vec![0xBB; 4 * 1024 * 1024];
    file.write_all(&data).unwrap();
    file.sync_all().unwrap();

    // Write zeros in the middle (512KB at offset 2MB)
    let offset = 2 * 1024 * 1024;
    let length = 512 * 1024;
    async_io.write_zeroes(offset, length, 2).unwrap();

    // Check completion
    let (user_data, result) = next_completion(async_io);
    assert_eq!(user_data, 2);
    assert_eq!(result, 0);

    // Verify the zeroed region reads as zeros
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut read_buf = vec![0; length as usize];
    file.read_exact(&mut read_buf).unwrap();
    assert!(
        read_buf.iter().all(|&b| b == 0),
        "Zeroed region should read as zeros"
    );

    // Verify data before zeroed region is intact
    file.seek(SeekFrom::Start(offset - 1024)).unwrap();
    let mut read_buf = vec![0; 1024];
    file.read_exact(&mut read_buf).unwrap();
    assert!(
        read_buf.iter().all(|&b| b == 0xBB),
        "Data before zeroed region should be intact"
    );

    // Verify data after zeroed region is intact
    file.seek(SeekFrom::Start(offset + length)).unwrap();
    let mut read_buf = vec![0; 1024];
    file.read_exact(&mut read_buf).unwrap();
    assert!(
        read_buf.iter().all(|&b| b == 0xBB),
        "Data after zeroed region should be intact"
    );
}

/// Tests punching multiple holes in an 8 MB file and verifying each hole
/// independently reads as zeroes.
pub(crate) fn test_punch_hole_multiple_operations(async_io: &mut dyn AsyncIo, file: &mut File) {
    // Write 8MB of data
    let data = vec![0xCC; 8 * 1024 * 1024];
    file.write_all(&data).unwrap();
    file.sync_all().unwrap();

    // Punch multiple holes
    async_io.punch_hole(1024 * 1024, 512 * 1024, 10).unwrap();
    async_io
        .punch_hole(3 * 1024 * 1024, 512 * 1024, 11)
        .unwrap();
    async_io
        .punch_hole(5 * 1024 * 1024, 512 * 1024, 12)
        .unwrap();

    // Check all completions
    let (user_data, result) = next_completion(async_io);
    assert_eq!(user_data, 10);
    assert_eq!(result, 0);

    let (user_data, result) = next_completion(async_io);
    assert_eq!(user_data, 11);
    assert_eq!(result, 0);

    let (user_data, result) = next_completion(async_io);
    assert_eq!(user_data, 12);
    assert_eq!(result, 0);

    // Verify all holes read as zeros
    file.seek(SeekFrom::Start(1024 * 1024)).unwrap();
    let mut read_buf = vec![0; 512 * 1024];
    file.read_exact(&mut read_buf).unwrap();
    assert!(read_buf.iter().all(|&b| b == 0));

    file.seek(SeekFrom::Start(3 * 1024 * 1024)).unwrap();
    file.read_exact(&mut read_buf).unwrap();
    assert!(read_buf.iter().all(|&b| b == 0));

    file.seek(SeekFrom::Start(5 * 1024 * 1024)).unwrap();
    file.read_exact(&mut read_buf).unwrap();
    assert!(read_buf.iter().all(|&b| b == 0));
}

/// Tests that a write zeroes that may unmap leaves zeroes in the range it
/// covers and nothing else changed, whatever `file` is.
pub(crate) fn test_write_zeroes_unmap(async_io: &mut dyn AsyncIo, file: &mut File) {
    const SIZE: usize = 1024 * 1024;
    const OFFSET: usize = 256 * 1024;
    const LENGTH: usize = 512 * 1024;

    file.write_all_at(&vec![0xAA; SIZE], 0).unwrap();
    file.sync_all().unwrap();

    async_io
        .write_zeroes_unmap(OFFSET as u64, LENGTH as u64, 7)
        .unwrap();
    let completion = wait_for_completion(async_io);
    assert_eq!((completion.user_data, completion.result), (7, 0));

    let mut read_buf = vec![0xFF; SIZE];
    file.read_exact_at(&mut read_buf, 0).unwrap();
    assert!(read_buf[..OFFSET].iter().all(|&b| b == 0xAA));
    assert!(read_buf[OFFSET..OFFSET + LENGTH].iter().all(|&b| b == 0));
    assert!(read_buf[OFFSET + LENGTH..].iter().all(|&b| b == 0xAA));
}

/// Tests that a backend's write zeroes that may unmap on a block device does
/// not go through `BLKDISCARD`, for a backend that was told that `file`, a
/// regular file, is one: `BLKDISCARD` fails on it with `ENOTTY`, whereas the
/// `fallocate` a write zeroes uses works.
pub(crate) fn test_write_zeroes_unmap_block_device_route(
    async_io: &mut dyn AsyncIo,
    file: &mut File,
) {
    // SAFETY: FFI call with a valid fd.
    let ret = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            0,
            4096,
        )
    };
    if ret != 0 {
        let err = io::Error::last_os_error();
        eprintln!("Skipping: the temporary file cannot have holes punched: {err}");
        return;
    }
    test_write_zeroes_unmap(async_io, file);
}

/// A loop device over a temporary file, removed on drop. Its file lives in
/// `TMPDIR`, which decides what the device supports.
pub(crate) struct LoopDevice {
    path: String,
    _backing: TempFile,
}

impl LoopDevice {
    const SIZE: u64 = 4 * 1024 * 1024;

    /// Creates the device, or returns `None`, saying why, if this environment
    /// cannot: it takes root and the `losetup` tool.
    pub(crate) fn new() -> Option<Self> {
        // SAFETY: FFI call without arguments.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Skipping: creating a loop device needs root");
            return None;
        }
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(Self::SIZE).unwrap();
        let output = match Command::new("losetup")
            .args(["-f", "--show", "--"])
            .arg(backing.as_path())
            .output()
        {
            Ok(output) if output.status.success() => output,
            result => {
                eprintln!("Skipping: losetup failed: {result:?}");
                return None;
            }
        };
        let path = String::from_utf8(output.stdout).unwrap().trim().to_string();
        Some(LoopDevice {
            path,
            _backing: backing,
        })
    }

    pub(crate) fn open(&self) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .unwrap()
    }
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        let _ = Command::new("losetup").args(["-d", &self.path]).status();
    }
}

/// How long [`slow_file_op`] takes, standing in for a slow block device.
const SLOW_OP_DELAY: Duration = Duration::from_secs(1);

/// Runs a [`BlockingOp`] on a regular file after [`SLOW_OP_DELAY`], like a
/// block device whose discards take that long.
pub(crate) fn slow_file_op(
    file: &mut File,
    op: BlockingOp,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    thread::sleep(SLOW_OP_DELAY);
    match op {
        BlockingOp::PunchHole | BlockingOp::WriteZeroesUnmap => {
            write_zeroes_unmap(file, false, offset, length)
        }
        BlockingOp::WriteZeroes => write_zeroes(file, false, offset, length),
    }
}

fn wait_for_completion(async_io: &mut dyn AsyncIo) -> AsyncIoCompletion {
    let deadline = Instant::now() + 10 * SLOW_OP_DELAY;
    loop {
        if let Some(completion) = async_io.next_completed_request() {
            return completion;
        }
        assert!(
            Instant::now() < deadline,
            "Timed out waiting for completion"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

/// Tests that a read submitted behind slow discard and write zeroes requests
/// completes without waiting for them, for a backend whose discard and write
/// zeroes run [`slow_file_op`].
pub(crate) fn test_slow_discard_does_not_block_queue(async_io: &mut dyn AsyncIo, file: &mut File) {
    file.write_all(&vec![0xAA; 64 * 1024]).unwrap();
    file.sync_all().unwrap();

    let start = Instant::now();
    async_io.punch_hole(0, 4096, 1).unwrap();
    async_io.write_zeroes(4096, 4096, 2).unwrap();
    async_io
        .read_to_vec(8192, OwnedIoBuffer::new(4096, 4096).unwrap(), 3)
        .unwrap();

    // The read completes first, before either slow request is done.
    let completion = wait_for_completion(async_io);
    let elapsed = start.elapsed();
    assert_eq!(completion.user_data, 3);
    assert_eq!(completion.result, 4096);
    assert!(
        elapsed < SLOW_OP_DELAY / 2,
        "Read waited {elapsed:?} behind slow discard and write zeroes"
    );
    let buffer = completion
        .buffer
        .expect("Read completion returns its buffer");
    assert!(buffer.as_slice().iter().all(|&b| b == 0xAA));

    // The slow requests then complete successfully.
    let mut completed = [wait_for_completion(async_io), wait_for_completion(async_io)]
        .map(|completion| (completion.user_data, completion.result));
    completed.sort_unstable();
    assert_eq!(completed, [(1, 0), (2, 0)]);

    file.seek(SeekFrom::Start(0)).unwrap();
    let mut read_buf = vec![0xFF; 8192];
    file.read_exact(&mut read_buf).unwrap();
    assert!(read_buf.iter().all(|&b| b == 0));
}
