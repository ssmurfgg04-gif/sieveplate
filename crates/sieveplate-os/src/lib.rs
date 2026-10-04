//! **sieveplate-os** — the OS layer: PID-1 init, the `spore` package
//! manager for real Arch Linux packages, and the bootable-image builder.

pub mod cpio;
pub mod init;
pub mod mkimage;
pub mod pkg;
