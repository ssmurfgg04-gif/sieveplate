//! **sieveplate-microvm** — the microVM cell kind (Layer 0 substrate).
//!
//! A microVM cell runs its cell logic inside a hardware-virtualized VM
//! (Firecracker or cloud-hypervisor) under Linux/KVM. This module:
//! 1. detects available hypervisors and KVM access — [`detect`];
//! 2. generates the exact API configuration a hypervisor consumes
//!    ([`firecracker_config`]) — golden-tested, no binary needed;
//! 3. launches VMs *only* when the pieces are actually present
//!    ([`spawn_vm`]) and returns [`MicroVmError::Unavailable`] with the
//!    precise missing ingredient otherwise.
//!
//! Honesty rules (the original plan's weakness): we never claim microVM
//! cells work in an environment where they were never run. `detect()` +
//! `spawn_vm()` make the capability checkable; CI exercises the config
//! generation and the unavailable-path everywhere, and the real boot path
//! wherever `/dev/kvm` exists.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Hypervisor {
    Firecracker,
    CloudHypervisor,
}

impl Hypervisor {
    pub fn binary_name(self) -> &'static str {
        match self {
            Hypervisor::Firecracker => "firecracker",
            Hypervisor::CloudHypervisor => "cloud-hypervisor",
        }
    }
}

/// A microVM cell's launch description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmSpec {
    /// Cell template the VM image implements (for closure-hash parity).
    pub template: String,
    pub vcpus: u8,
    pub mem_mib: u32,
    /// Unikernel / kernel image (ELF). Firecracker wants a PVH linux image
    /// or a Unikraft-built unikernel.
    pub kernel: PathBuf,
    /// Root filesystem (ext4, read-only recommended). Unikernels skip it.
    #[serde(default)]
    pub rootfs: Option<PathBuf>,
    /// Extra kernel boot args.
    #[serde(default)]
    pub boot_args: String,
}

impl Default for VmSpec {
    fn default() -> Self {
        VmSpec {
            template: "builtin:kv".into(),
            vcpus: 1,
            mem_mib: 128,
            kernel: PathBuf::from("vmlinux"),
            rootfs: None,
            boot_args: "console=ttyS0 reboot=k panic=1".into(),
        }
    }
}

/// One found hypervisor.
#[derive(Debug, Clone)]
pub struct Detected {
    pub hypervisor: Hypervisor,
    pub binary: PathBuf,
    pub kvm: bool,
}

fn find_binary(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn kvm_available() -> bool {
    Path::new("/dev/kvm").exists()
}

/// Which hypervisors can actually run here (binary in PATH + KVM)?
pub fn detect() -> Vec<Detected> {
    let kvm = kvm_available();
    [Hypervisor::Firecracker, Hypervisor::CloudHypervisor]
        .iter()
        .filter_map(|h| {
            find_binary(h.binary_name()).map(|binary| Detected {
                hypervisor: *h,
                binary,
                kvm,
            })
        })
        .collect()
}

/// The Firecracker API config (boot-source + drives + machine). Written to
/// a file and passed to `firecracker --api-sock ... --config-file ...`.
pub fn firecracker_config(spec: &VmSpec, socket_path: &Path) -> serde_json::Value {
    let mut drives = vec![serde_json::json!({
        "drive_id": "kernel",
        "path_on_host": spec.kernel,
        "is_root_device": spec.rootfs.is_none(),
        "is_read_only": true,
    })];
    if let Some(rootfs) = &spec.rootfs {
        drives.push(serde_json::json!({
            "drive_id": "rootfs",
            "path_on_host": rootfs,
            "is_root_device": true,
            "is_read_only": false,
        }));
    }
    // Kernel-only boot: root device is the kernel drive itself.
    if spec.rootfs.is_some() {
        drives[0]["is_root_device"] = serde_json::json!(false);
    }
    serde_json::json!({
        "boot-source": {
            "kernel_image_path": spec.kernel,
            "boot_args": spec.boot_args,
        },
        "drives": drives,
        "machine-config": {
            "vcpu_count": spec.vcpus,
            "mem_size_mib": spec.mem_mib,
            "smt": false,
        },
        "vsock": {
            "guest_cid": 3,
            "uds_path": socket_path,
        }
    })
}

#[derive(Debug, thiserror::Error)]
pub enum MicroVmError {
    #[error("microVM unavailable: {0}")]
    Unavailable(String),
    #[error("launch failed: {0}")]
    Launch(String),
}

/// A launched VM cell.
pub struct VmHandle {
    pub child: tokio::process::Child,
    pub hypervisor: Hypervisor,
}

impl std::fmt::Debug for VmHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmHandle")
            .field("hypervisor", &self.hypervisor)
            .finish()
    }
}

/// Launch a VM cell — but ONLY when everything needed exists. A missing
/// binary, missing KVM, or missing kernel image is a hard, explicit
/// `Unavailable` listing exactly what is missing. No fake runs.
pub async fn spawn_vm(spec: &VmSpec) -> Result<VmHandle, MicroVmError> {
    let mut missing: Vec<String> = Vec::new();
    let detected = detect();
    if detected.is_empty() {
        missing.push("no hypervisor binary in PATH (firecracker | cloud-hypervisor)".into());
    }
    let chosen = detected.iter().find(|d| d.kvm).ok_or_else(|| {
        MicroVmError::Unavailable(format!(
            "KVM not available ({}/dev/kvm missing or no binary): {}",
            if kvm_available() { "" } else { "/dev/kvm" },
            if missing.is_empty() {
                "ready".to_string()
            } else {
                missing.join("; ")
            }
        ))
    })?;
    if !spec.kernel.exists() {
        missing.push(format!(
            "kernel image '{}' not found",
            spec.kernel.display()
        ));
    }
    if !missing.is_empty() {
        return Err(MicroVmError::Unavailable(missing.join("; ")));
    }

    match chosen.hypervisor {
        Hypervisor::Firecracker => {
            let sock =
                std::env::temp_dir().join(format!("sieveplate-fc-{}.sock", std::process::id()));
            let cfg = firecracker_config(spec, &sock);
            let cfg_path =
                std::env::temp_dir().join(format!("sieveplate-fc-{}.json", std::process::id()));
            std::fs::write(
                &cfg_path,
                serde_json::to_vec_pretty(&cfg).map_err(|e| MicroVmError::Launch(e.to_string()))?,
            )
            .map_err(|e| MicroVmError::Launch(e.to_string()))?;
            let child = tokio::process::Command::new(&chosen.binary)
                .arg("--api-sock")
                .arg(&sock)
                .arg("--config-file")
                .arg(&cfg_path)
                .spawn()
                .map_err(|e| MicroVmError::Launch(e.to_string()))?;
            Ok(VmHandle {
                child,
                hypervisor: chosen.hypervisor,
            })
        }
        Hypervisor::CloudHypervisor => {
            let mut cmd = tokio::process::Command::new(&chosen.binary);
            cmd.arg("--kernel").arg(&spec.kernel);
            if let Some(rootfs) = &spec.rootfs {
                cmd.arg("--disk").arg(format!("path={}", rootfs.display()));
            }
            cmd.arg("--cpus").arg(spec.vcpus.to_string());
            cmd.arg("--memory").arg(format!("size={}M", spec.mem_mib));
            let child = cmd
                .spawn()
                .map_err(|e| MicroVmError::Launch(e.to_string()))?;
            Ok(VmHandle {
                child,
                hypervisor: chosen.hypervisor,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firecracker_config_golden_shape() {
        let spec = VmSpec {
            rootfs: Some("/tmp/rootfs.ext4".into()),
            ..Default::default()
        };
        let cfg = firecracker_config(&spec, Path::new("/tmp/v.sock"));
        assert_eq!(cfg["machine-config"]["vcpu_count"], 1);
        assert_eq!(cfg["machine-config"]["mem_size_mib"], 128);
        let drives = cfg["drives"].as_array().unwrap();
        assert_eq!(drives.len(), 2);
        assert_eq!(drives[0]["is_root_device"], serde_json::json!(false));
        assert_eq!(drives[1]["is_root_device"], serde_json::json!(true));
        assert_eq!(cfg["vsock"]["uds_path"], "/tmp/v.sock");
    }

    #[test]
    fn unikernel_style_kernel_only_boot() {
        let spec = VmSpec::default(); // no rootfs
        let cfg = firecracker_config(&spec, Path::new("/tmp/v.sock"));
        let drives = cfg["drives"].as_array().unwrap();
        assert_eq!(drives.len(), 1);
        assert_eq!(drives[0]["is_root_device"], serde_json::json!(true));
    }

    #[test]
    fn spawn_without_kvm_is_honest_unavailable() {
        // In CI (no /dev/kvm, no firecracker binary) this must return
        // Unavailable, not pretend to run.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(spawn_vm(&VmSpec {
                kernel: PathBuf::from("/definitely/not/here/vmlinux"),
                ..Default::default()
            }))
            .unwrap_err();
        assert!(matches!(err, MicroVmError::Unavailable(_)), "{err}");
    }
}
