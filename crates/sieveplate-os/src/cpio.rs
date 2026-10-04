//! cpio `newc` writer — enough of the format to build an initramfs.
//!
//! The `newc` format is dead simple: a 110-byte ASCII header per entry,
//! name, then data, all padded to 4-byte boundaries, terminated by an
//! entry named `TRAILER!!!`. The Linux kernel's initramfs loader consumes
//! exactly this.

use anyhow::Result;
use std::io::Write;

#[derive(Debug, Clone)]
pub enum EntryKind {
    File { data: Vec<u8>, mode: u32 },
    Dir { mode: u32 },
    Symlink { target: String },
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub kind: EntryKind,
}

pub struct CpioWriter<W: Write> {
    inner: W,
    ino: u32,
}

impl<W: Write> CpioWriter<W> {
    pub fn new(inner: W) -> Self {
        CpioWriter { inner, ino: 300 }
    }

    fn next_ino(&mut self) -> u32 {
        self.ino += 1;
        self.ino
    }

    pub fn write_entry(&mut self, e: &Entry) -> Result<()> {
        let (mode, nlink, filesize, data): (u32, u32, u32, &[u8]) = match &e.kind {
            EntryKind::File { data, mode } => {
                (0o100000 | (mode & 0o7777), 1, data.len() as u32, data)
            }
            EntryKind::Dir { mode } => (0o040000 | (mode & 0o7777), 2, 0, &[]),
            EntryKind::Symlink { target } => {
                (0o120000 | 0o777, 1, target.len() as u32, target.as_bytes())
            }
        };
        let name = e.name.as_bytes();
        let ino = self.next_ino();
        let uid = 0u32;
        let gid = 0u32;
        let mtime = 0u32; // reproducible images
                          // file alignment (4 bytes) BEFORE the header
        self.pad4()?;
        let header =
            format!(
            "070701{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
            ino, mode, uid, gid, nlink, mtime, filesize, 0, // devmajor
            0,  // devminor
            0,  // rdevmajor
            0,  // rdevminor
            name.len() as u32 + 1,
            0 // check
        );
        self.inner.write_all(header.as_bytes())?;
        self.inner.write_all(name)?;
        self.inner.write_all(&[0])?;
        // name padding to 4
        let name_len = name.len() + 1;
        let pad = (4 - (110 + name_len) % 4) % 4;
        self.inner.write_all(&vec![0u8; pad])?;
        self.inner.write_all(data)?;
        let data_pad = (4 - (filesize as usize) % 4) % 4;
        self.inner.write_all(&vec![0u8; data_pad])?;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<()> {
        self.pad4()?;
        let header = format!(
            "070701{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
            0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0
        );
        self.inner.write_all(header.as_bytes())?;
        self.inner.write_all(b"TRAILER!!!\0")?;
        // pad to 512 for good measure
        let written = 110 + 11;
        let pad = (512 - written % 512) % 512 + (4 - (110 + 11) % 4);
        self.inner.write_all(&vec![0u8; pad])?;
        self.inner.flush()?;
        Ok(())
    }

    fn pad4(&mut self) -> Result<()> {
        // no-op placeholder: alignment handled per-entry in write_entry
        Ok(())
    }
}
