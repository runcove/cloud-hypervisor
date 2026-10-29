// Copyright © 2023 Intel Corporation
//
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Copyright © 2023 Crusoe Energy Systems LLC
//

use std::fs::File;
use std::os::unix::io::AsRawFd;

use log::warn;
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AioDataIo, AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, AsyncIoResult,
    BlockingOffload, BlockingOp, BlockingOpFn, OFFLOAD_DEPTH, WorkerThreadInit, offload_fn,
};
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::sparse::{punch_hole, write_zeroes};
use crate::{SECTOR_SIZE, is_block_device, probe_direct_alignment};

pub(super) struct RawAio {
    raw_file: File,
    data_io: AioDataIo,
    alignment: Option<u64>,
    is_block_device: bool,
    // Runs discard and write zeroes off the queue thread on block devices.
    offload: Option<BlockingOffload>,
}

impl RawAio {
    pub(super) fn new(raw_file: File, direct: bool, queue_depth: u32) -> BlockResult<Self> {
        let offload_fn = offload_fn(is_block_device(raw_file.as_raw_fd()));
        Self::with_offload(raw_file, direct, queue_depth, offload_fn)
    }

    fn with_offload(
        raw_file: File,
        direct: bool,
        queue_depth: u32,
        offload_fn: Option<BlockingOpFn>,
    ) -> BlockResult<Self> {
        let data_io =
            AioDataIo::new(queue_depth).map_err(|e| BlockError::new(BlockErrorKind::Io, e))?;
        let is_block_device = is_block_device(raw_file.as_raw_fd());
        let alignment = if direct {
            Some(probe_direct_alignment(raw_file.as_raw_fd()).unwrap_or(SECTOR_SIZE))
        } else {
            None
        };
        let offload = offload_fn.and_then(|run| {
            raw_file
                .try_clone()
                .and_then(|file| BlockingOffload::new(file, data_io.notifier(), OFFLOAD_DEPTH, run))
                .inspect_err(|e| {
                    warn!("Failed to set up discard offload, running it synchronously: {e}");
                })
                .ok()
        });

        Ok(RawAio {
            raw_file,
            data_io,
            alignment,
            is_block_device,
            offload,
        })
    }
}

impl AsyncIo for RawAio {
    fn notifier(&self) -> &EventFd {
        self.data_io.notifier()
    }

    fn alignment(&self) -> Option<u64> {
        self.alignment
    }

    fn submit_data_operation(&mut self, op: AsyncIoOperation) -> AsyncIoResult<()> {
        let is_read = op.is_read();

        let fd = self.raw_file.as_raw_fd();
        self.data_io.submit_operation(fd, op).map_err(|e| {
            if is_read {
                AsyncIoError::ReadVectored(e)
            } else {
                AsyncIoError::WriteVectored(e)
            }
        })
    }

    fn fsync(&mut self, user_data: Option<u64>) -> AsyncIoResult<()> {
        let fd = self.raw_file.as_raw_fd();
        if let Some(user_data) = user_data {
            self.data_io
                .submit_fsync(fd, user_data)
                .map_err(AsyncIoError::Fsync)?;
        } else {
            // SAFETY: FFI call with a valid fd
            unsafe { libc::fsync(fd) };
        }

        Ok(())
    }

    fn can_submit_punch_hole_or_write_zeroes(&self) -> bool {
        self.offload
            .as_ref()
            .is_none_or(BlockingOffload::has_capacity)
    }

    fn set_worker_thread_init(&mut self, init: WorkerThreadInit) {
        if let Some(offload) = &mut self.offload {
            offload.set_thread_init(init);
        }
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.data_io
            .next_completion()
            .or_else(|| self.offload.as_mut()?.next_completion())
    }

    fn punch_hole(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        if let Some(offload) = &mut self.offload {
            offload.submit(BlockingOp::PunchHole, offset, length, user_data);
            return Ok(());
        }
        // Linux AIO has no IOCB command for fallocate, so otherwise perform
        // the operation synchronously and signal completion via the
        // completion list, matching the pattern used by the sync backend
        // (RawSync).
        punch_hole(&mut self.raw_file, self.is_block_device, offset, length)
            .map_err(AsyncIoError::PunchHole)?;
        self.data_io
            .inject_completion(AsyncIoCompletion::new(user_data, 0, None));

        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, length: u64, user_data: u64) -> AsyncIoResult<()> {
        if let Some(offload) = &mut self.offload {
            offload.submit(BlockingOp::WriteZeroes, offset, length, user_data);
            return Ok(());
        }
        // Same as punch_hole().
        write_zeroes(&mut self.raw_file, self.is_block_device, offset, length)
            .map_err(AsyncIoError::WriteZeroes)?;
        self.data_io
            .inject_completion(AsyncIoCompletion::new(user_data, 0, None));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::formats::raw::test_helpers;

    #[test]
    fn test_punch_hole() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawAio::new(file.try_clone().unwrap(), false, 128).unwrap();
        test_helpers::test_punch_hole(&mut async_io, &mut file);
    }

    #[test]
    fn test_write_zeroes() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawAio::new(file.try_clone().unwrap(), false, 128).unwrap();
        test_helpers::test_write_zeroes(&mut async_io, &mut file);
    }

    #[test]
    fn test_punch_hole_multiple_operations() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawAio::new(file.try_clone().unwrap(), false, 128).unwrap();
        test_helpers::test_punch_hole_multiple_operations(&mut async_io, &mut file);
    }

    #[test]
    fn test_offload_follows_block_device_detection() {
        let temp_file = TempFile::new().unwrap();
        let file = temp_file.into_file();
        let async_io = RawAio::new(file.try_clone().unwrap(), false, 128).unwrap();
        assert!(async_io.offload.is_none());
        assert!(async_io.can_submit_punch_hole_or_write_zeroes());
        let mut async_io =
            RawAio::with_offload(file, false, 128, Some(test_helpers::slow_file_op)).unwrap();
        assert!(async_io.offload.is_some());
        // The offload depth, not the ring depth, bounds requests in flight.
        for user_data in 0..OFFLOAD_DEPTH as u64 {
            assert!(async_io.can_submit_punch_hole_or_write_zeroes());
            async_io.punch_hole(0, 4096, user_data).unwrap();
        }
        assert!(!async_io.can_submit_punch_hole_or_write_zeroes());
    }

    #[test]
    fn test_slow_discard_does_not_block_queue() {
        let temp_file = TempFile::new().unwrap();
        let mut file = temp_file.into_file();
        let mut async_io = RawAio::with_offload(
            file.try_clone().unwrap(),
            false,
            128,
            Some(test_helpers::slow_file_op),
        )
        .unwrap();
        test_helpers::test_slow_discard_does_not_block_queue(&mut async_io, &mut file);
    }
}
