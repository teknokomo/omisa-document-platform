# Parser packaging notes

The package scripts build into an explicit staging directory and do not enable or start services. Review the target-specific security and compatibility gates before deployment.

## Reproducibility and offline runtime

* Ubuntu 24.04 amd64 build image is pinned by OCI digest in
  `rootfs/ubuntu-noble-amd64.lock`.
* Top-level packages are exact-version pinned. Assembly captures the complete
  downloaded Debian dependency closure and SHA-256 for every `.deb`, wheel,
  rootfs file, font and Tesseract traineddata file.
* `requirements-hashed.txt` contains the complete resolved wheel closure and
  hashes. Installation is `--no-index --require-hashes`.
* Tika 3.3.2 is fetched at build time only and checked against the repository
  SHA-256. Runtime has no package manager operation, URL input, or network.
* `sbom.spdx.json`, `packages.tsv`, and hash manifests are build outputs.

Run (network is required only here):

```sh
./packaging/rootfs/assemble.sh /tmp/omisa-rootfs-build
```

## DynamicUser and bubblewrap ownership

A non-setuid bwrap invoked by a `DynamicUser=` process creates a one-ID user
namespace. The caller's outer dynamic UID is represented as UID 0 inside.
Bind-mount permission checks still resolve to that same outer UID. Therefore
the worker remains namespace UID 0, bwrap drops all capabilities, and the
0700/0400 DynamicUser-owned job tree works without chown, idmapped mounts,
subuid ranges, sudo, or gateway privilege. Switching to namespace UID 65534
is incorrect for this one-ID map: it is unmapped and cannot traverse the job.

Security depends on all of: root-owned immutable bwrap/rootfs/policy files,
`NoNewPrivileges`, empty capability sets, private network, and seccomp denying
namespace/mount/socket syscalls after bwrap setup. Validate this exact behavior
on target kernel/systemd with `tests/target-systemd.sh` before deployment.

## Seccomp

`seccomp/build.py` uses libseccomp `seccomp_export_bpf()` and emits native cBPF
files accepted through bwrap's inherited `--seccomp FD`. Native, OCR and legacy
artifacts are separate and selected fail-closed. Their baseline policy is a
high-confidence denylist because CPython, Poppler, Tesseract, Java and
LibreOffice do not have a stable practical syscall allowlist. Tightening must
follow target syscall traces and regression tests.

## Accept=yes model

`omisa-parser.socket` uses `Accept=yes` and explicitly maps to
`omisa-parser@.service`. Each accepted connection starts one template instance,
one DynamicUser and one service cgroup. Standard input/output are the accepted
stream. Aggregate slice limits prevent concurrent parser jobs from multiplying
host consumption; `MaxConnections=1` serializes active jobs.

Render environment-specific service values into a staging directory:

```sh
./packaging/render-target.sh /tmp/omisa-units omisa omisa 12345
```

## Target validation gate

1. Rebuild using a dated Ubuntu snapshot mirror (or retain the immutable OCI
   build artifact plus all `.deb` files); current public apt repository URLs
   can garbage-collect exact versions.
2. Verify Ubuntu systemd 255 unit syntax and run the exact socket/template.
3. Verify two sequential connections produce distinct instance IDs/cgroups;
   concurrent connection obeys MaxConnections; disconnect/timeout cleans up.
4. Run bwrap probes for input read, output create, no host home/network/sockets,
   denied mount/unshare/ptrace/BPF/io_uring, and cgroup OOM/PID/disk/inode caps.
5. Provision `/etc/omisa-parser/broker-hmac` root-owned 0400 and design a
   non-disclosing gateway attestation interface. Do not give the gateway the
   root key or sudo.
6. Resolve integration requirements outside this package: bounded one-page-at-a-
   time OCR raster storage, proven Tika OCR/embedded recursion disablement,
   history capability/SCM_RIGHTS client integration, and process-tree timeout.

Until all gates pass, release remains **NO-GO**.
