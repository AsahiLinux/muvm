use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::ffi::{c_long, c_void, CString};
use std::fs::{read_to_string, remove_file, File};
use std::io::{IoSlice, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::exit;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::{fs, mem, ptr, thread};

use anyhow::Result;
use nix::errno::Errno;
use nix::fcntl::readlink;
use nix::libc::{
    c_int, c_ulonglong, pid_t, user_regs_struct, SYS_close, SYS_dup3, SYS_mmap, SYS_munmap,
    SYS_openat, AT_FDCWD, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MAP_SHARED, O_CLOEXEC, O_RDWR,
    PROT_READ, PROT_WRITE,
};
use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::socket::getsockopt;
use nix::sys::socket::sockopt::PeerCredentials;
use nix::sys::stat::fstat;
use nix::sys::uio::{process_vm_writev, RemoteIoVec};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{mkstemp, read, Pid};
use nix::{ioctl_read, NixPath};

use crate::guest::bridge::common;
use crate::guest::bridge::common::{
    Client, CrossDomainHeader, CrossDomainResource, GemHandleFinalizer, MessageResourceFinalizer,
    ProtocolHandler, SendPacket, StreamRecvResult, StreamSendResult, PAGE_SIZE,
};

const X11_OPCODE_QUERY_EXTENSION: u8 = 98;
const X11_OPCODE_NOP: u8 = 127;
const X11_REPLY: u8 = 1;
const X11_GENERIC_EVENT: u8 = 35;
const DRI3_OPCODE_VERSION: u8 = 0;
const DRI3_OPCODE_OPEN: u8 = 1;
const DRI3_OPCODE_PIXMAP_FROM_BUFFER: u8 = 2;
const DRI3_OPCODE_FENCE_FROM_FD: u8 = 4;
const SYNC_OPCODE_DESTROY_FENCE: u8 = 17;
const DRI3_OPCODE_PIXMAP_FROM_BUFFERS: u8 = 7;
const PRESENT_OPCODE_PRESENT_PIXMAP: u8 = 1;
pub const SHM_TEMPLATE: &str = "/dev/shm/krshm-XXXXXX";
pub const SHM_DIR: &str = "/dev/shm/";
const SYSCALL_INSTR: u32 = 0xd4000001;
static SYSCALL_OFFSET: OnceLock<usize> = OnceLock::new();
const CROSS_DOMAIN_CHANNEL_TYPE_X11: u32 = 0x11;
const CROSS_DOMAIN_ID_TYPE_SHM: u32 = 5;
const CROSS_DOMAIN_CMD_FUTEX_NEW: u8 = 8;
const CROSS_DOMAIN_CMD_FUTEX_SIGNAL: u8 = 9;
const CROSS_DOMAIN_CMD_FUTEX_DESTROY: u8 = 10;

#[repr(C)]
#[derive(Debug, Default)]
struct ExportedHandle {
    fs_id: u64,
    handle: u64,
}

const VIRTIO_IOC_MAGIC: u8 = b'v';
const VIRTIO_IOC_TYPE_EXPORT_FD: u8 = 1;

ioctl_read!(
    virtio_export_handle,
    VIRTIO_IOC_MAGIC,
    VIRTIO_IOC_TYPE_EXPORT_FD,
    ExportedHandle
);

#[repr(C)]
struct CrossDomainFutexNew {
    hdr: CrossDomainHeader,
    fs_id: u64,
    handle: u64,
    id: u32,
    pad: u32,
}

#[repr(C)]
struct CrossDomainFutexSignal {
    hdr: CrossDomainHeader,
    id: u32,
    pad: u32,
}

#[repr(C)]
struct CrossDomainFutexDestroy {
    hdr: CrossDomainHeader,
    id: u32,
    pad: u32,
}

enum X11ResourceFinalizer {
    Gem(GemHandleFinalizer),
    Futex(u32),
}

impl MessageResourceFinalizer for X11ResourceFinalizer {
    type Handler = X11ProtocolHandler;

    fn finalize(self, client: &mut Client<X11ProtocolHandler>) -> Result<()> {
        match self {
            X11ResourceFinalizer::Gem(fin) => fin.finalize(client)?,
            X11ResourceFinalizer::Futex(xid) => {
                client.protocol_handler.futex_watchers.remove(&xid).unwrap();
                let ft_destroy_msg_size = mem::size_of::<CrossDomainFutexDestroy>();
                let ft_msg = CrossDomainFutexDestroy {
                    hdr: CrossDomainHeader::new(
                        CROSS_DOMAIN_CMD_FUTEX_DESTROY,
                        ft_destroy_msg_size as u16,
                    ),
                    id: xid,
                    pad: 0,
                };
                client
                    .gpu_ctx
                    .submit_cmd(&ft_msg, ft_destroy_msg_size, None, None)?;
            },
        }
        Ok(())
    }
}

struct X11ProtocolHandler {
    // futex_watchers gets dropped first
    futex_watchers: HashMap<u32, FutexWatcherThread>,
    got_first_req: bool,
    seq_no: u16,
    got_first_resp: bool,
    dri3_ext_opcode: Option<u8>,
    dri3_qe_resp_seq: Option<u16>,
    sync_ext_opcode: Option<u8>,
    sync_qe_resp_seq: Option<u16>,
    present_ext_opcode: Option<u8>,
    present_qe_resp_seq: Option<u16>,
}

impl ProtocolHandler for X11ProtocolHandler {
    type ResourceFinalizer = X11ResourceFinalizer;

    const CHANNEL_TYPE: u32 = CROSS_DOMAIN_CHANNEL_TYPE_X11;

    fn new() -> X11ProtocolHandler {
        X11ProtocolHandler {
            futex_watchers: HashMap::new(),
            got_first_req: false,
            seq_no: 1,
            dri3_ext_opcode: None,
            dri3_qe_resp_seq: None,
            sync_ext_opcode: None,
            sync_qe_resp_seq: None,
            present_qe_resp_seq: None,
            present_ext_opcode: None,
            got_first_resp: false,
        }
    }

    fn process_recv_stream(
        this: &mut Client<Self>,
        data: &[u8],
        resources: &mut VecDeque<CrossDomainResource>,
    ) -> Result<StreamRecvResult> {
        if !this.protocol_handler.got_first_resp {
            this.protocol_handler.got_first_resp = true;
            let size = u16::from_ne_bytes(data[6..8].try_into().unwrap()) as usize * 4 + 8;
            return Ok(StreamRecvResult::Processed {
                consumed_bytes: size,
                fds: Vec::new(),
            });
        }
        if data.len() < 32 {
            eprintln!(
                "X11 message truncated (expected at least 32 bytes, got {})",
                data.len(),
            );
            return Ok(StreamRecvResult::WantMore);
        }
        let mut fds = Vec::new();
        for ident in resources.drain(..) {
            fds.push(this.virtgpu_id_to_prime(ident)?);
        }
        let seq_no = u16::from_ne_bytes(data[2..4].try_into().unwrap());
        let is_reply = data[0] == X11_REPLY;
        let is_generic = data[0] == X11_GENERIC_EVENT;
        let len = if is_reply || is_generic {
            u32::from_ne_bytes(data[4..8].try_into().unwrap()) as usize * 4
        } else {
            0
        } + 32;
        if is_reply {
            if Some(seq_no) == this.protocol_handler.dri3_qe_resp_seq {
                this.protocol_handler.dri3_qe_resp_seq = None;
                this.protocol_handler.dri3_ext_opcode = extract_opcode_from_qe_resp(data);
            } else if Some(seq_no) == this.protocol_handler.sync_qe_resp_seq {
                this.protocol_handler.sync_qe_resp_seq = None;
                this.protocol_handler.sync_ext_opcode = extract_opcode_from_qe_resp(data);
            } else if Some(seq_no) == this.protocol_handler.present_qe_resp_seq {
                this.protocol_handler.present_qe_resp_seq = None;
                this.protocol_handler.present_ext_opcode = extract_opcode_from_qe_resp(data);
            }
        }
        Ok(StreamRecvResult::Processed {
            consumed_bytes: len,
            fds,
        })
    }

    fn process_send_stream(
        this: &mut Client<Self>,
        buf: &mut [u8],
    ) -> Result<StreamSendResult<X11ResourceFinalizer>> {
        let mut resources = Vec::new();
        let mut finalizers = Vec::new();
        if !this.protocol_handler.got_first_req {
            this.protocol_handler.got_first_req = true;
            return Ok(StreamSendResult::Processed {
                consumed_bytes: buf.len(),
                resources,
                finalizers,
            });
        }
        if buf.len() < 4 {
            eprintln!(
                "X11 message truncated (expected at least 4 bytes, got {})",
                buf.len(),
            );
            return Ok(StreamSendResult::WantMore);
        }
        let mut req_len = u16::from_ne_bytes(buf[2..4].try_into().unwrap()) as usize * 4;
        if req_len == 0 {
            if buf.len() < 8 {
                eprintln!(
                    "X11 message truncated (expected at least 8 bytes, got {})",
                    buf.len(),
                );
                return Ok(StreamSendResult::WantMore);
            }
            req_len = u32::from_ne_bytes(buf[4..8].try_into().unwrap()) as usize * 4;
        }
        if buf[0] == X11_OPCODE_QUERY_EXTENSION {
            let namelen = u16::from_ne_bytes(buf[4..6].try_into().unwrap()) as usize;
            let name = String::from_utf8_lossy(&buf[8..(8 + namelen)]);
            if name == "DRI3" {
                this.protocol_handler.dri3_qe_resp_seq = Some(this.protocol_handler.seq_no);
            } else if name == "SYNC" {
                this.protocol_handler.sync_qe_resp_seq = Some(this.protocol_handler.seq_no)
            } else if name == "Present" {
                this.protocol_handler.present_qe_resp_seq = Some(this.protocol_handler.seq_no);
            }
        } else if Some(buf[0]) == this.protocol_handler.dri3_ext_opcode {
            if buf[1] == DRI3_OPCODE_VERSION {
                buf[8] = buf[8].min(3);
            } else if buf[1] == DRI3_OPCODE_OPEN {
                buf[0] = X11_OPCODE_NOP;
                let mut reply = vec![
                    1,
                    1,
                    (this.protocol_handler.seq_no & 0xff) as u8,
                    (this.protocol_handler.seq_no >> 8) as u8,
                ];
                reply.extend_from_slice(&[0u8; 28]);
                let render = File::options()
                    .read(true)
                    .write(true)
                    .open("/dev/dri/renderD128")?;
                this.send_queue.push_back(SendPacket {
                    data: reply,
                    fds: vec![render.into()],
                });
            } else if buf[1] == DRI3_OPCODE_PIXMAP_FROM_BUFFER {
                let fd = this.request_fds.remove(0);
                let (res, finalizer) = this.vgpu_id_from_prime(fd)?;
                resources.push(res);
                finalizers.push(X11ResourceFinalizer::Gem(finalizer));
            } else if buf[1] == DRI3_OPCODE_FENCE_FROM_FD {
                let xid = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
                let fd = this.request_fds.remove(0);
                let filename = readlink(format!("/proc/self/fd/{}", fd.as_raw_fd()).as_str())?;
                let filename = filename.to_string_lossy();
                let creds = getsockopt(&this.socket.as_fd(), PeerCredentials)?;
                let res = Self::create_cross_vm_futex(this, fd, xid, creds.pid(), filename)?;
                resources.push(res);
            } else if buf[1] == DRI3_OPCODE_PIXMAP_FROM_BUFFERS {
                let num_bufs = buf[12] as usize;
                for fd in this.request_fds.drain(..num_bufs).collect::<Vec<_>>() {
                    let (res, finalizer) = this.vgpu_id_from_prime(fd)?;
                    resources.push(res);
                    finalizers.push(X11ResourceFinalizer::Gem(finalizer));
                }
            }
        } else if Some(buf[0]) == this.protocol_handler.sync_ext_opcode {
            if buf[1] == SYNC_OPCODE_DESTROY_FENCE {
                let xid = u32::from_ne_bytes(buf[4..8].try_into().unwrap());
                finalizers.push(X11ResourceFinalizer::Futex(xid));
            }
        } else if Some(buf[0]) == this.protocol_handler.present_ext_opcode
            && buf[1] == PRESENT_OPCODE_PRESENT_PIXMAP
        {
            /* TODO: Implement GPU fence passing here when we have it. */
        }
        this.protocol_handler.seq_no = this.protocol_handler.seq_no.wrapping_add(1);
        Ok(StreamSendResult::Processed {
            finalizers,
            resources,
            consumed_bytes: req_len,
        })
    }

    fn process_vgpu_extra(this: &mut Client<Self>, cmd: u8) -> Result<()> {
        if cmd != CROSS_DOMAIN_CMD_FUTEX_SIGNAL {
            return Err(Errno::EINVAL.into());
        }
        // SAFETY: vmm will put a valid cross domain message at that address
        let recv = unsafe {
            (this.gpu_ctx.channel_ring.address as *const CrossDomainFutexSignal)
                .as_ref()
                .unwrap()
        };
        this.protocol_handler.process_futex_signal(recv)
    }
}

impl X11ProtocolHandler {
    fn ptrace_all_threads(pid: Pid) -> Result<Vec<PtracedPid>> {
        let mut tids = Vec::new();
        for entry in fs::read_dir(format!("/proc/{pid}/task"))? {
            let entry = match entry {
                Err(_) => continue,
                Ok(a) => a,
            };
            let tid = Pid::from_raw(
                entry
                    .file_name()
                    .into_string()
                    .or(Err(Errno::EIO))?
                    .parse()?,
            );
            if let Err(e) = ptrace::attach(tid) {
                // This could be a race (thread exited), so keep going
                // unless this is the top-level PID
                if tid == pid {
                    return Err(e.into());
                }
                eprintln!("ptrace::attach({pid}, ...) failed (continuing)");
                continue;
            }
            let ptid = PtracedPid(tid);
            wait_for_stop(ptid.pid())?;
            tids.push(ptid);
        }
        Ok(tids)
    }

    fn replace_futex_storage(
        my_fd: RawFd,
        pid: Pid,
        shmem_path: &str,
        shmem_file: &mut File,
    ) -> Result<()> {
        let traced = Self::ptrace_all_threads(pid)?;

        let mut data = [0; 4];
        read(my_fd, &mut data)?;
        shmem_file.write_all(&data)?;

        // TODO: match st_dev too to avoid false positives
        let my_ino = fstat(my_fd)?.st_ino;
        let mut fds_to_replace = Vec::new();
        for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
            let entry = entry?;
            if let Ok(file) = File::options().open(entry.path()) {
                if fstat(file.as_raw_fd())?.st_ino == my_ino {
                    fds_to_replace.push(entry.file_name().to_string_lossy().parse::<i32>()?);
                }
            }
        }
        let mut pages_to_replace = Vec::new();
        for line in read_to_string(format!("/proc/{pid}/maps"))?.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            let ino: u64 = f[4].parse()?;
            if ino == my_ino {
                let addr = usize::from_str_radix(f[0].split('-').next().unwrap(), 16)?;
                pages_to_replace.push(addr);
            }
        }
        RemoteCaller::with(pid, |caller| {
            let scratch_page = caller.mmap(
                0,
                PAGE_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                0,
                0,
            )?;
            let path_cstr = CString::new(shmem_path).unwrap();
            process_vm_writev(
                pid,
                &[IoSlice::new(path_cstr.as_bytes_with_nul())],
                &[RemoteIoVec {
                    base: scratch_page,
                    len: path_cstr.len(),
                }],
            )?;
            let remote_shm = caller.open(scratch_page, O_CLOEXEC | O_RDWR, 0o600)?;
            for fd in fds_to_replace {
                caller.dup2(remote_shm, fd)?;
            }
            for page in pages_to_replace {
                caller.mmap(
                    page,
                    PAGE_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_FIXED,
                    remote_shm,
                    0,
                )?;
            }
            caller.munmap(scratch_page, PAGE_SIZE)?;
            caller.close(remote_shm)?;
            Ok(())
        })?;
        // This detaches all the traced threads
        mem::drop(traced);
        Ok(())
    }

    fn create_cross_vm_futex(
        this: &mut Client<Self>,
        memfd: OwnedFd,
        xid: u32,
        pid: pid_t,
        filename: Cow<'_, str>,
    ) -> Result<CrossDomainResource> {
        // Allow everything in /dev/shm (including paths with trailing '(deleted)')
        let shmem_file = if filename.starts_with(SHM_DIR) {
            File::from(memfd)
        } else if cfg!(not(target_arch = "aarch64")) {
            return Err(Errno::EOPNOTSUPP.into());
        } else {
            let (fd, shmem_path) = mkstemp(SHM_TEMPLATE)?;
            let mut shmem_file = unsafe { File::from_raw_fd(fd) };
            let ret = Self::replace_futex_storage(
                memfd.as_raw_fd(),
                Pid::from_raw(pid),
                shmem_path.as_os_str().to_str().unwrap(),
                &mut shmem_file,
            );
            remove_file(&shmem_path)?;
            ret?;
            shmem_file
        };

        let mut handle: ExportedHandle = Default::default();
        unsafe { virtio_export_handle(shmem_file.as_raw_fd(), &mut handle) }?;

        let addr = FutexPtr(unsafe {
            mmap(
                None,
                4.try_into().unwrap(),
                ProtFlags::PROT_WRITE | ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED,
                shmem_file,
                0,
            )?
            .as_ptr()
        });
        let initial_value =
            unsafe { AtomicU32::from_ptr(addr.0 as *mut u32) }.load(Ordering::Relaxed);

        let ft_new_msg_size = mem::size_of::<CrossDomainFutexNew>();
        let ft_msg = CrossDomainFutexNew {
            hdr: CrossDomainHeader::new(CROSS_DOMAIN_CMD_FUTEX_NEW, ft_new_msg_size as u16),
            id: xid,
            fs_id: handle.fs_id,
            handle: handle.handle,
            pad: 0,
        };
        this.gpu_ctx
            .submit_cmd(&ft_msg, ft_new_msg_size, None, None)?;
        let fd = this.gpu_ctx.fd.as_raw_fd() as c_int;
        this.protocol_handler
            .futex_watchers
            .insert(xid, FutexWatcherThread::new(fd, xid, addr, initial_value));
        Ok(CrossDomainResource {
            identifier: xid,
            identifier_type: CROSS_DOMAIN_ID_TYPE_SHM,
            identifier_size: 0,
        })
    }

    fn process_futex_signal(&mut self, recv: &CrossDomainFutexSignal) -> Result<()> {
        let watcher = match self.futex_watchers.get(&recv.id) {
            Some(a) => a,
            None => {
                eprintln!("Unknown futex id {}", recv.id);
                return Ok(());
            },
        };

        watcher.signal();

        Ok(())
    }
}

#[derive(Clone)]
struct FutexPtr(*mut c_void);

unsafe impl Send for FutexPtr {}

impl Drop for FutexPtr {
    fn drop(&mut self) {
        unsafe {
            munmap(NonNull::new_unchecked(self.0), 4).unwrap();
        }
    }
}

fn extract_opcode_from_qe_resp(data: &[u8]) -> Option<u8> {
    if data[8] != 0 {
        Some(data[9])
    } else {
        None
    }
}

struct FutexWatcherThread {
    join_handle: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
    futex: FutexPtr,
}

unsafe fn wake_futex(futex: *mut c_void, val3: u32) {
    let op = nix::libc::FUTEX_WAKE_BITSET;
    let val = c_int::MAX;
    let timeout = ptr::null::<()>();
    let uaddr2 = ptr::null::<()>();
    unsafe {
        nix::libc::syscall(nix::libc::SYS_futex, futex, op, val, timeout, uaddr2, val3);
    }
}

impl FutexWatcherThread {
    fn new(fd: c_int, xid: u32, futex: FutexPtr, initial_value: u32) -> FutexWatcherThread {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown2 = shutdown.clone();
        let futex2 = futex.clone();
        let handle = thread::spawn(move || {
            let uaddr = futex2;
            let op = nix::libc::FUTEX_WAIT_BITSET;
            let timeout = ptr::null::<()>();
            let uaddr2 = ptr::null::<()>();
            let val3 = 1u32;
            let mut val = initial_value;
            let atomic_val = unsafe { AtomicU32::from_ptr(uaddr.0 as *mut u32) };
            loop {
                if shutdown2.load(Ordering::SeqCst) {
                    break;
                }
                unsafe {
                    nix::libc::syscall(
                        nix::libc::SYS_futex,
                        uaddr.0,
                        op,
                        val,
                        timeout,
                        uaddr2,
                        val3,
                    );
                }
                val = atomic_val.load(Ordering::SeqCst);
                let ft_signal_msg_size = mem::size_of::<CrossDomainFutexSignal>();
                let ft_signal_cmd = CrossDomainFutexSignal {
                    hdr: CrossDomainHeader::new(
                        CROSS_DOMAIN_CMD_FUTEX_SIGNAL,
                        ft_signal_msg_size as u16,
                    ),
                    id: xid,
                    pad: 0,
                };
                common::submit_cmd_raw(fd, &ft_signal_cmd, ft_signal_msg_size, None, None).unwrap();
            }
        });
        FutexWatcherThread {
            futex,
            join_handle: Some(handle),
            shutdown,
        }
    }

    fn signal(&self) {
        unsafe {
            wake_futex(self.futex.0, !1);
        }
    }
}

impl Drop for FutexWatcherThread {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let atomic_val = unsafe { AtomicU32::from_ptr(self.futex.0 as *mut u32) };
        let v = atomic_val.load(Ordering::SeqCst);
        atomic_val.store(!v, Ordering::SeqCst);
        unsafe {
            wake_futex(self.futex.0, !0);
        }
        self.join_handle.take().unwrap().join().unwrap();
    }
}

#[allow(dead_code)]
struct RemoteCaller {
    pid: Pid,
    regs: user_regs_struct,
}

impl RemoteCaller {
    // This is arch-specific, so gate it off of x86_64 builds done for CI purposes
    #[cfg(target_arch = "aarch64")]
    fn with<R, F>(pid: Pid, f: F) -> Result<R>
    where
        F: FnOnce(&RemoteCaller) -> Result<R>,
    {
        let old_regs = ptrace::getregs(pid)?;

        // Find the vDSO and the address of a syscall instruction within it
        let (vdso_start, _) = find_vdso(Some(pid))?;
        let syscall_addr = vdso_start + SYSCALL_OFFSET.get().unwrap();

        let mut regs = old_regs;
        regs.pc = syscall_addr as u64;
        ptrace::setregs(pid, regs)?;
        let res = f(&RemoteCaller { regs, pid })?;
        ptrace::setregs(pid, old_regs)?;
        Ok(res)
    }

    fn dup2(&self, oldfd: i32, newfd: i32) -> Result<i32> {
        self.syscall(SYS_dup3, [oldfd as u64, newfd as u64, 0, 0, 0, 0])
            .map(|x| x as i32)
    }

    fn close(&self, fd: i32) -> Result<i32> {
        self.syscall(SYS_close, [fd as u64, 0, 0, 0, 0, 0])
            .map(|x| x as i32)
    }

    fn mmap(
        &self,
        addr: usize,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: usize,
    ) -> Result<usize> {
        self.syscall(
            SYS_mmap,
            [
                addr as u64,
                length as u64,
                prot as u64,
                flags as u64,
                fd as u64,
                offset as u64,
            ],
        )
        .map(|x| x as usize)
    }

    fn munmap(&self, addr: usize, length: usize) -> Result<i32> {
        self.syscall(SYS_munmap, [addr as u64, length as u64, 0, 0, 0, 0])
            .map(|x| x as i32)
    }

    fn open(&self, path: usize, flags: i32, mode: i32) -> Result<i32> {
        self.syscall(
            SYS_openat,
            [
                AT_FDCWD as u64,
                path as u64,
                flags as u64,
                mode as u64,
                0,
                0,
            ],
        )
        .map(|x| x as i32)
    }

    // This is arch-specific, so gate it off of x86_64 builds done for CI purposes
    #[cfg(target_arch = "aarch64")]
    fn syscall(&self, syscall_no: c_long, args: [c_ulonglong; 6]) -> Result<c_ulonglong> {
        let mut regs = self.regs;
        regs.regs[..6].copy_from_slice(&args);
        regs.regs[8] = syscall_no as c_ulonglong;
        ptrace::setregs(self.pid, regs)?;
        ptrace::step(self.pid, None)?;
        let evt = waitpid(self.pid, Some(WaitPidFlag::__WALL))?;
        if !matches!(evt, WaitStatus::Stopped(_, _)) {
            unimplemented!();
        }
        regs = ptrace::getregs(self.pid)?;
        Ok(regs.regs[0])
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn with<R, F>(_pid: Pid, _f: F) -> Result<R>
    where
        F: FnOnce(&RemoteCaller) -> Result<R>,
    {
        Err(Errno::EOPNOTSUPP.into())
    }
    #[cfg(not(target_arch = "aarch64"))]
    fn syscall(&self, _syscall_no: c_long, _args: [c_ulonglong; 6]) -> Result<c_ulonglong> {
        Err(Errno::EOPNOTSUPP.into())
    }
}

fn wait_for_stop(pid: Pid) -> Result<()> {
    loop {
        let event = waitpid(pid, Some(WaitPidFlag::__WALL))?;
        match event {
            WaitStatus::Stopped(_, sig) => {
                if sig == Signal::SIGSTOP {
                    return Ok(());
                } else {
                    ptrace::cont(pid, sig)?;
                }
            },
            _ => unimplemented!(),
        }
    }
}

struct PtracedPid(Pid);

impl PtracedPid {
    fn pid(&self) -> Pid {
        self.0
    }
}

impl Drop for PtracedPid {
    fn drop(&mut self) {
        if ptrace::detach(self.0, None).is_err() {
            eprintln!("Failed to ptrace::detach({}) (continuing)", self.0);
        }
    }
}

fn find_vdso(pid: Option<Pid>) -> Result<(usize, usize), Errno> {
    let path = format!(
        "/proc/{}/maps",
        pid.map(|a| a.to_string()).unwrap_or("self".into())
    );

    for line in read_to_string(path).unwrap().lines() {
        if line.ends_with("[vdso]") {
            let a = line.find('-').ok_or(Errno::EINVAL)?;
            let b = line.find(' ').ok_or(Errno::EINVAL)?;
            let start = usize::from_str_radix(&line[..a], 16).or(Err(Errno::EINVAL))?;
            let end = usize::from_str_radix(&line[a + 1..b], 16).or(Err(Errno::EINVAL))?;

            return Ok((start, end));
        }
    }

    Err(Errno::EINVAL)
}

pub fn start_x11bridge(display: u32) {
    let sock_path = format!("/tmp/.X11-unix/X{display}");

    // Look for a syscall instruction in the vDSO. We assume all processes map
    // the same vDSO (which should be true if they are running under the same
    // kernel!)
    let (vdso_start, vdso_end) = find_vdso(None).unwrap();
    for off in (0..(vdso_end - vdso_start)).step_by(4) {
        let addr = vdso_start + off;
        let val = unsafe { std::ptr::read(addr as *const u32) };
        if val == SYSCALL_INSTR {
            SYSCALL_OFFSET.set(off).unwrap();
            break;
        }
    }
    if SYSCALL_OFFSET.get().is_none() {
        eprintln!("Failed to find syscall instruction in vDSO");
        exit(1);
    }

    common::bridge_loop::<X11ProtocolHandler>(&sock_path)
}
