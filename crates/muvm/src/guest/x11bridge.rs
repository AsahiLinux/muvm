use anyhow::Result;
use nix::errno::Errno;
use nix::fcntl::readlink;
use nix::libc::{
    c_int, c_ulonglong, c_void, off_t, pid_t, user_regs_struct, SYS_close, SYS_dup3, SYS_mmap,
    SYS_munmap, SYS_openat, AT_FDCWD, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MAP_SHARED, O_CLOEXEC,
    O_RDWR, PROT_READ, PROT_WRITE,
};
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::socket::sockopt::PeerCredentials;
use nix::sys::socket::{
    getsockopt, recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags, RecvMsg,
};
use nix::sys::stat::fstat;
use nix::sys::uio::{process_vm_writev, RemoteIoVec};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{mkstemp, read, Pid};
use nix::{cmsg_space, ioctl_read, ioctl_readwrite, ioctl_write_ptr, NixPath};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::ffi::{c_long, CString};
use std::fs::{read_to_string, remove_file, File};
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::exit;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::{env, fs, mem, ptr, slice, thread};

const PAGE_SIZE: usize = 4096;

const VIRTGPU_CONTEXT_PARAM_CAPSET_ID: u64 = 0x0001;
const VIRTGPU_CONTEXT_PARAM_NUM_RINGS: u64 = 0x0002;
const VIRTGPU_CONTEXT_PARAM_POLL_RINGS_MASK: u64 = 0x0003;
const CAPSET_CROSS_DOMAIN: u64 = 5;
const CROSS_DOMAIN_CHANNEL_RING: u32 = 1;
const VIRTGPU_BLOB_MEM_GUEST: u32 = 0x0001;
const VIRTGPU_BLOB_MEM_HOST3D: u32 = 0x0002;
const VIRTGPU_BLOB_FLAG_USE_MAPPABLE: u32 = 0x0001;
const VIRTGPU_BLOB_FLAG_USE_SHAREABLE: u32 = 0x0002;
const VIRTGPU_EVENT_FENCE_SIGNALED: u32 = 0x90000000;
const CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB: u32 = 1;
const CROSS_DOMAIN_ID_TYPE_SHM: u32 = 5;

const X11_OPCODE_CREATE_PIXMAP: u8 = 53;
const X11_OPCODE_FREE_PIXMAP: u8 = 54;
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

#[repr(C)]
#[derive(Debug, Default)]
struct ExportedHandle {
    fs_id: u64,
    handle: u64,
}

const SYSCALL_INSTR: u32 = 0xd4000001;
static SYSCALL_OFFSET: OnceLock<usize> = OnceLock::new();

const VIRTIO_IOC_MAGIC: u8 = b'v';
const VIRTIO_IOC_TYPE_EXPORT_FD: u8 = 1;

ioctl_read!(
    virtio_export_handle,
    VIRTIO_IOC_MAGIC,
    VIRTIO_IOC_TYPE_EXPORT_FD,
    ExportedHandle
);

#[repr(C)]
#[derive(Default)]
struct DrmVirtgpuContextInit {
    num_params: u32,
    pad: u32,
    ctx_set_params: u64,
}

#[repr(C)]
#[derive(Default)]
struct DrmVirtgpuContextSetParam {
    param: u64,
    value: u64,
}

#[rustfmt::skip]
ioctl_readwrite!(drm_virtgpu_context_init, 'd', 0x40 + 0xb, DrmVirtgpuContextInit);

#[repr(C)]
#[derive(Default)]
struct DrmVirtgpuResourceCreateBlob {
    blob_mem: u32,
    blob_flags: u32,
    bo_handle: u32,
    res_handle: u32,
    size: u64,
    pad: u32,
    cmd_size: u32,
    cmd: u64,
    blob_id: u64,
}

#[rustfmt::skip]
ioctl_readwrite!(drm_virtgpu_resource_create_blob, 'd', 0x40 + 0xa, DrmVirtgpuResourceCreateBlob);

#[repr(C)]
#[derive(Default)]
struct DrmVirtgpuMap {
    offset: u64,
    handle: u32,
    pad: u32,
}

#[rustfmt::skip]
ioctl_readwrite!(drm_virtgpu_map, 'd', 0x40 + 0x1, DrmVirtgpuMap);

#[repr(C)]
#[derive(Default)]
struct DrmGemClose {
    handle: u32,
    pad: u32,
}

impl DrmGemClose {
    fn new(handle: u32) -> DrmGemClose {
        DrmGemClose {
            handle,
            ..DrmGemClose::default()
        }
    }
}

#[rustfmt::skip]
ioctl_write_ptr!(drm_gem_close, 'd', 0x9, DrmGemClose);

#[repr(C)]
#[derive(Default)]
struct DrmPrimeHandle {
    handle: u32,
    flags: u32,
    fd: i32,
}

#[rustfmt::skip]
ioctl_readwrite!(drm_prime_handle_to_fd, 'd', 0x2d, DrmPrimeHandle);
#[rustfmt::skip]
ioctl_readwrite!(drm_prime_fd_to_handle, 'd', 0x2e, DrmPrimeHandle);

#[repr(C)]
#[derive(Default)]
struct DrmEvent {
    ty: u32,
    length: u32,
}

const VIRTGPU_EXECBUF_RING_IDX: u32 = 0x04;
#[repr(C)]
#[derive(Default)]
struct DrmVirtgpuExecbuffer {
    flags: u32,
    size: u32,
    command: u64,
    bo_handles: u64,
    num_bo_handles: u32,
    fence_fd: i32,
    ring_idx: u32,
    pad: u32,
}

#[rustfmt::skip]
ioctl_readwrite!(drm_virtgpu_execbuffer, 'd', 0x40 + 0x2, DrmVirtgpuExecbuffer);

#[repr(C)]
#[derive(Default)]
struct DrmVirtgpuResourceInfo {
    bo_handle: u32,
    res_handle: u32,
    size: u32,
    blob_mem: u32,
}

#[rustfmt::skip]
ioctl_readwrite!(drm_virtgpu_resource_info, 'd', 0x40 + 0x5, DrmVirtgpuResourceInfo);

#[repr(C)]
#[derive(Default)]
struct CrossDomainHeader {
    cmd: u8,
    fence_ctx_idx: u8,
    cmd_size: u16,
    pad: u32,
}

impl CrossDomainHeader {
    fn new(cmd: u8, cmd_size: u16) -> CrossDomainHeader {
        CrossDomainHeader {
            cmd,
            cmd_size,
            ..CrossDomainHeader::default()
        }
    }
}

const CROSS_DOMAIN_CMD_INIT: u8 = 1;
const CROSS_DOMAIN_CMD_POLL: u8 = 3;
const CROSS_DOMAIN_CHANNEL_TYPE_X11: u32 = 0x11;
#[repr(C)]
#[derive(Default)]
struct CrossDomainInit {
    hdr: CrossDomainHeader,
    query_ring_id: u32,
    channel_ring_id: u32,
    channel_type: u32,
}

#[repr(C)]
#[derive(Default)]
struct CrossDomainPoll {
    hdr: CrossDomainHeader,
    pad: u64,
}

impl CrossDomainPoll {
    fn new() -> CrossDomainPoll {
        CrossDomainPoll {
            hdr: CrossDomainHeader::new(
                CROSS_DOMAIN_CMD_POLL,
                mem::size_of::<CrossDomainPoll>() as u16,
            ),
            ..CrossDomainPoll::default()
        }
    }
}

#[repr(C)]
pub struct CrossDomainFutexNew {
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

const CROSS_DOMAIN_MAX_IDENTIFIERS: usize = 4;
const CROSS_DOMAIN_CMD_SEND: u8 = 4;
const CROSS_DOMAIN_CMD_RECEIVE: u8 = 5;
const CROSS_DOMAIN_CMD_FUTEX_NEW: u8 = 8;
const CROSS_DOMAIN_CMD_FUTEX_SIGNAL: u8 = 9;
pub const CROSS_DOMAIN_CMD_FUTEX_DESTROY: u8 = 10;

#[repr(C)]
struct CrossDomainSendReceive<T: ?Sized> {
    hdr: CrossDomainHeader,
    num_identifiers: u32,
    opaque_data_size: u32,
    identifiers: [u32; CROSS_DOMAIN_MAX_IDENTIFIERS],
    identifier_types: [u32; CROSS_DOMAIN_MAX_IDENTIFIERS],
    identifier_sizes: [u32; CROSS_DOMAIN_MAX_IDENTIFIERS],
    data: T,
}

const CROSS_DOMAIN_SR_TAIL_SIZE: usize = PAGE_SIZE - mem::size_of::<CrossDomainSendReceive<()>>();

struct GpuRing {
    handle: u32,
    res_id: u32,
    address: *mut c_void,
    fd: OwnedFd,
}

impl GpuRing {
    fn new(fd: &OwnedFd) -> Result<GpuRing> {
        let fd = fd.try_clone().unwrap();
        let mut create_blob = DrmVirtgpuResourceCreateBlob {
            size: PAGE_SIZE as u64,
            blob_mem: VIRTGPU_BLOB_MEM_GUEST,
            blob_flags: VIRTGPU_BLOB_FLAG_USE_MAPPABLE,
            ..DrmVirtgpuResourceCreateBlob::default()
        };
        unsafe {
            drm_virtgpu_resource_create_blob(fd.as_raw_fd() as c_int, &mut create_blob)?;
        }
        let mut map = DrmVirtgpuMap {
            handle: create_blob.bo_handle,
            ..DrmVirtgpuMap::default()
        };
        unsafe {
            drm_virtgpu_map(fd.as_raw_fd() as c_int, &mut map)?;
        }
        let ptr = unsafe {
            mmap(
                None,
                NonZeroUsize::new(PAGE_SIZE).unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                &fd,
                map.offset as off_t,
            )?
            .as_ptr()
        };
        Ok(GpuRing {
            fd,
            handle: create_blob.bo_handle,
            res_id: create_blob.res_handle,
            address: ptr,
        })
    }
}

impl Drop for GpuRing {
    fn drop(&mut self) {
        unsafe {
            munmap(NonNull::new(self.address).unwrap(), PAGE_SIZE).unwrap();
            let close = DrmGemClose::new(self.handle);
            drm_gem_close(self.fd.as_raw_fd() as c_int, &close).unwrap();
        }
    }
}

struct Context {
    fd: OwnedFd,
    channel_ring: GpuRing,
    query_ring: GpuRing,
}

impl Context {
    fn new() -> Result<Context> {
        let mut params = [
            DrmVirtgpuContextSetParam {
                param: VIRTGPU_CONTEXT_PARAM_CAPSET_ID,
                value: CAPSET_CROSS_DOMAIN,
            },
            DrmVirtgpuContextSetParam {
                param: VIRTGPU_CONTEXT_PARAM_NUM_RINGS,
                value: 2,
            },
            DrmVirtgpuContextSetParam {
                param: VIRTGPU_CONTEXT_PARAM_POLL_RINGS_MASK,
                value: 1 << CROSS_DOMAIN_CHANNEL_RING,
            },
        ];
        let mut init = DrmVirtgpuContextInit {
            num_params: 3,
            pad: 0,
            ctx_set_params: params.as_mut_ptr() as u64,
        };
        let fd: OwnedFd = File::options()
            .write(true)
            .read(true)
            .open("/dev/dri/renderD128")?
            .into();
        unsafe {
            drm_virtgpu_context_init(fd.as_raw_fd() as c_int, &mut init)?;
        }

        let query_ring = GpuRing::new(&fd)?;
        let channel_ring = GpuRing::new(&fd)?;
        let this = Context {
            fd,
            query_ring,
            channel_ring,
        };
        let init_cmd = CrossDomainInit {
            hdr: CrossDomainHeader::new(
                CROSS_DOMAIN_CMD_INIT,
                mem::size_of::<CrossDomainInit>() as u16,
            ),
            query_ring_id: this.query_ring.res_id,
            channel_ring_id: this.channel_ring.res_id,
            channel_type: CROSS_DOMAIN_CHANNEL_TYPE_X11,
        };
        this.submit_cmd(&init_cmd, mem::size_of::<CrossDomainInit>(), None, None)?;
        this.poll_cmd()?;
        Ok(this)
    }
    fn submit_cmd<T>(
        &self,
        cmd: &T,
        cmd_size: usize,
        ring_idx: Option<u32>,
        ring_handle: Option<u32>,
    ) -> Result<()> {
        submit_cmd_raw(
            self.fd.as_raw_fd() as c_int,
            cmd,
            cmd_size,
            ring_idx,
            ring_handle,
        )
    }
    fn poll_cmd(&self) -> Result<()> {
        let cmd = CrossDomainPoll::new();
        self.submit_cmd(
            &cmd,
            mem::size_of::<CrossDomainPoll>(),
            Some(CROSS_DOMAIN_CHANNEL_RING),
            None,
        )
    }
}

fn submit_cmd_raw<T>(
    fd: c_int,
    cmd: &T,
    cmd_size: usize,
    ring_idx: Option<u32>,
    ring_handle: Option<u32>,
) -> Result<()> {
    let cmd_buf = cmd as *const T as *const u8;
    let mut exec = DrmVirtgpuExecbuffer {
        command: cmd_buf as u64,
        size: cmd_size as u32,
        ..DrmVirtgpuExecbuffer::default()
    };
    if let Some(ring_idx) = ring_idx {
        exec.ring_idx = ring_idx;
        exec.flags = VIRTGPU_EXECBUF_RING_IDX;
    }
    let ring_handle = &ring_handle;
    if let Some(ring_handle) = ring_handle {
        exec.bo_handles = ring_handle as *const u32 as u64;
        exec.num_bo_handles = 1;
    }
    unsafe {
        drm_virtgpu_execbuffer(fd, &mut exec)?;
    }
    if ring_handle.is_some() {
        unimplemented!();
    }
    Ok(())
}

struct DebugLoopInner {
    ls_remote: TcpStream,
    ls_local: TcpStream,
}

struct DebugLoop(Option<DebugLoopInner>);

impl DebugLoop {
    fn new() -> DebugLoop {
        if !env::var("X11VG_DEBUG")
            .map(|x| x == "1")
            .unwrap_or_default()
        {
            return DebugLoop(None);
        }
        let ls_remote_l = TcpListener::bind(("0.0.0.0", 6001)).unwrap();
        let ls_local_jh = thread::spawn(|| TcpStream::connect(("0.0.0.0", 6001)).unwrap());
        let ls_remote = ls_remote_l.accept().unwrap().0;
        let ls_local = ls_local_jh.join().unwrap();
        DebugLoop(Some(DebugLoopInner {
            ls_remote,
            ls_local,
        }))
    }
    fn loop_remote(&mut self, data: &[u8]) {
        if let Some(this) = &mut self.0 {
            this.ls_remote.write_all(data).unwrap();
            let mut trash = vec![0; data.len()];
            this.ls_local.read_exact(&mut trash).unwrap();
        }
    }
    fn loop_local(&mut self, data: &[u8]) {
        if let Some(this) = &mut self.0 {
            this.ls_local.write_all(data).unwrap();
            let mut trash = vec![0; data.len()];
            this.ls_remote.read_exact(&mut trash).unwrap();
        }
    }
}

struct SendPacket {
    data: Vec<u8>,
    fds: Vec<OwnedFd>,
}

struct Client {
    // futex_watchers must be dropped before gpu_ctx, so it goes first
    futex_watchers: HashMap<u32, FutexWatcherThread>,
    gpu_ctx: Context,
    socket: UnixStream,
    got_first_req: bool,
    got_first_resp: bool,
    dri3_ext_opcode: Option<u8>,
    dri3_qe_resp_seq: Option<u16>,
    sync_ext_opcode: Option<u8>,
    sync_qe_resp_seq: Option<u16>,
    present_ext_opcode: Option<u8>,
    present_qe_resp_seq: Option<u16>,
    seq_no: u16,
    reply_tail: usize,
    reply_head: Vec<u8>,
    request_tail: usize,
    request_head: Vec<u8>,
    request_fds: Vec<OwnedFd>,
    debug_loop: DebugLoop,
    buffers_for_pixmap: HashMap<u32, Vec<OwnedFd>>,
    send_queue: VecDeque<SendPacket>,
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

fn extract_opcode_from_qe_resp(data: &[u8], ptr: usize) -> Option<u8> {
    if data[ptr + 8] != 0 {
        Some(data[ptr + 9])
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
                submit_cmd_raw(fd, &ft_signal_cmd, ft_signal_msg_size, None, None).unwrap();
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

#[derive(Debug)]
enum ClientEvent {
    None,
    StartSend,
    StopSend,
    Close,
}

impl Client {
    fn new(socket: UnixStream) -> Result<Client> {
        Ok(Client {
            socket,
            gpu_ctx: Context::new()?,
            got_first_req: false,
            dri3_ext_opcode: None,
            dri3_qe_resp_seq: None,
            sync_ext_opcode: None,
            sync_qe_resp_seq: None,
            present_qe_resp_seq: None,
            present_ext_opcode: None,
            seq_no: 1,
            reply_tail: 0,
            reply_head: Vec::new(),
            got_first_resp: false,
            request_tail: 0,
            request_head: Vec::new(),
            request_fds: Vec::new(),
            futex_watchers: HashMap::new(),
            debug_loop: DebugLoop::new(),
            buffers_for_pixmap: HashMap::new(),
            send_queue: VecDeque::new(),
        })
    }
    fn process_socket(&mut self, events: EpollFlags) -> Result<ClientEvent> {
        if events.contains(EpollFlags::EPOLLIN) {
            let queue_empty = self.send_queue.is_empty();
            if self.process_socket_recv()? {
                return Ok(ClientEvent::Close);
            }
            if queue_empty && !self.send_queue.is_empty() {
                return Ok(ClientEvent::StartSend);
            }
        }
        if events.contains(EpollFlags::EPOLLOUT) {
            self.process_socket_send()?;
            if self.send_queue.is_empty() {
                return Ok(ClientEvent::StopSend);
            }
        }
        Ok(ClientEvent::None)
    }

    fn process_socket_send(&mut self) -> Result<()> {
        let mut msg = self.send_queue.pop_front().unwrap();
        let fds: Vec<RawFd> = msg.fds.iter().map(|a| a.as_raw_fd()).collect();
        let cmsgs = if fds.is_empty() {
            Vec::new()
        } else {
            vec![ControlMessage::ScmRights(&fds)]
        };
        match sendmsg::<()>(
            self.socket.as_raw_fd(),
            &[IoSlice::new(&msg.data)],
            &cmsgs,
            MsgFlags::empty(),
            None,
        ) {
            Ok(sent) => {
                if sent < msg.data.len() {
                    msg.data = msg.data.split_off(sent);
                    self.send_queue.push_front(SendPacket {
                        data: msg.data.split_off(sent),
                        fds: Vec::new(),
                    });
                }
            },
            Err(Errno::EAGAIN) => self.send_queue.push_front(msg),
            Err(e) => return Err(e.into()),
        };
        Ok(())
    }
    fn process_socket_recv(&mut self) -> Result<bool> {
        let mut fdspace = cmsg_space!([RawFd; CROSS_DOMAIN_MAX_IDENTIFIERS]);
        let mut ring_msg = CrossDomainSendReceive {
            hdr: CrossDomainHeader::new(CROSS_DOMAIN_CMD_SEND, 0),
            num_identifiers: 0,
            opaque_data_size: 0,
            identifiers: [0; CROSS_DOMAIN_MAX_IDENTIFIERS],
            identifier_types: [0; CROSS_DOMAIN_MAX_IDENTIFIERS],
            identifier_sizes: [0; CROSS_DOMAIN_MAX_IDENTIFIERS],
            data: [0u8; CROSS_DOMAIN_SR_TAIL_SIZE],
        };
        let recv_buf = if self.request_tail > 0 {
            assert!(self.request_head.is_empty());
            assert!(self.request_fds.is_empty());
            let len = self.request_tail.min(ring_msg.data.len());
            &mut ring_msg.data[..len]
        } else {
            let head_len = self.request_head.len();
            ring_msg.data[..head_len].copy_from_slice(&self.request_head);
            self.request_head.clear();
            &mut ring_msg.data[head_len..]
        };
        let mut ioslice = [IoSliceMut::new(recv_buf)];
        let msg: RecvMsg<()> = recvmsg(
            self.socket.as_raw_fd(),
            &mut ioslice,
            Some(&mut fdspace),
            MsgFlags::empty(),
        )?;
        for cmsg in msg.cmsgs()? {
            match cmsg {
                ControlMessageOwned::ScmRights(rf) => {
                    for fd in rf {
                        self.request_fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                    }
                },
                _ => unimplemented!(),
            }
        }
        let len = if let Some(iov) = msg.iovs().next() {
            iov.len()
        } else {
            return Ok(true);
        };
        let buf = &mut ring_msg.data[..len];
        self.debug_loop.loop_local(buf);
        let mut fd_xids = [None; CROSS_DOMAIN_MAX_IDENTIFIERS];
        let mut cur_fd_for_msg = 0;
        let mut fences_to_destroy = Vec::new();
        if !self.got_first_req {
            self.got_first_req = true;
        } else if self.request_tail > 0 {
            assert!(self.request_fds.is_empty());
            self.request_tail -= buf.len();
        } else if self.request_tail == 0 {
            let mut ptr = 0;
            while ptr < buf.len() {
                if buf.len() - ptr < 4 {
                    eprintln!(
                        "X11 message truncated (expected at least 4 bytes, got {}:{} = {})",
                        ptr,
                        buf.len(),
                        buf.len() - ptr
                    );
                    break;
                }
                let mut req_len =
                    u16::from_ne_bytes(buf[(ptr + 2)..(ptr + 4)].try_into().unwrap()) as usize * 4;
                if req_len == 0 {
                    if buf.len() - ptr < 8 {
                        eprintln!(
                            "X11 message truncated (expected at least 8 bytes, got {}:{} = {})",
                            ptr,
                            buf.len(),
                            buf.len() - ptr
                        );
                        break;
                    }
                    req_len = u32::from_ne_bytes(buf[(ptr + 4)..(ptr + 8)].try_into().unwrap())
                        as usize
                        * 4;
                }
                if buf[ptr] == X11_OPCODE_QUERY_EXTENSION {
                    let namelen =
                        u16::from_ne_bytes(buf[(ptr + 4)..(ptr + 6)].try_into().unwrap()) as usize;
                    let name = String::from_utf8_lossy(&buf[(ptr + 8)..(ptr + 8 + namelen)]);
                    if name == "DRI3" {
                        self.dri3_qe_resp_seq = Some(self.seq_no);
                    } else if name == "SYNC" {
                        self.sync_qe_resp_seq = Some(self.seq_no)
                    } else if name == "Present" {
                        self.present_qe_resp_seq = Some(self.seq_no);
                    }
                } else if Some(buf[ptr]) == self.dri3_ext_opcode {
                    if buf[ptr + 1] == DRI3_OPCODE_VERSION {
                        buf[ptr + 8] = buf[ptr + 8].min(3);
                    } else if buf[ptr + 1] == DRI3_OPCODE_OPEN {
                        buf[ptr] = X11_OPCODE_NOP;
                        let mut reply =
                            vec![1, 1, (self.seq_no & 0xff) as u8, (self.seq_no >> 8) as u8];
                        reply.extend_from_slice(&[0u8; 28]);
                        let render = File::options()
                            .read(true)
                            .write(true)
                            .open("/dev/dri/renderD128")?;
                        self.send_queue.push_back(SendPacket {
                            data: reply,
                            fds: vec![render.into()],
                        });
                    } else if buf[ptr + 1] == DRI3_OPCODE_PIXMAP_FROM_BUFFER {
                        let xid = u32::from_ne_bytes(buf[(ptr + 4)..(ptr + 8)].try_into().unwrap());
                        fd_xids[cur_fd_for_msg] = Some(xid);
                        cur_fd_for_msg += 1;
                    } else if buf[ptr + 1] == DRI3_OPCODE_FENCE_FROM_FD {
                        let xid =
                            u32::from_ne_bytes(buf[(ptr + 8)..(ptr + 12)].try_into().unwrap());
                        fd_xids[cur_fd_for_msg] = Some(xid);
                        cur_fd_for_msg += 1;
                    } else if buf[ptr + 1] == DRI3_OPCODE_PIXMAP_FROM_BUFFERS {
                        let xid = u32::from_ne_bytes(buf[(ptr + 4)..(ptr + 8)].try_into().unwrap());
                        let num_bufs = buf[ptr + 12] as usize;
                        for i in 0..num_bufs {
                            fd_xids[cur_fd_for_msg + i] = Some(xid);
                        }
                        cur_fd_for_msg += num_bufs;
                    }
                } else if Some(buf[ptr]) == self.sync_ext_opcode {
                    if buf[ptr + 1] == SYNC_OPCODE_DESTROY_FENCE {
                        let xid = u32::from_ne_bytes(buf[(ptr + 4)..(ptr + 8)].try_into().unwrap());
                        fences_to_destroy.push(xid);
                    }
                } else if Some(buf[ptr]) == self.present_ext_opcode {
                    if buf[ptr + 1] == PRESENT_OPCODE_PRESENT_PIXMAP {
                        /* TODO: Implement GPU fence passing here when we have it. */
                    }
                } else if buf[ptr] == X11_OPCODE_CREATE_PIXMAP {
                    let xid = u32::from_ne_bytes(buf[(ptr + 4)..(ptr + 8)].try_into().unwrap());
                    self.buffers_for_pixmap.insert(xid, Vec::new());
                } else if buf[ptr] == X11_OPCODE_FREE_PIXMAP {
                    let xid = u32::from_ne_bytes(buf[(ptr + 4)..(ptr + 8)].try_into().unwrap());
                    self.buffers_for_pixmap.remove(&xid);
                }
                self.seq_no = self.seq_no.wrapping_add(1);
                ptr += req_len;
            }
            if ptr < buf.len() {
                self.request_head = buf[ptr..].to_vec();
            } else {
                self.request_tail = ptr - buf.len();
            }
        }
        if self.request_head.is_empty() {
            assert_eq!(cur_fd_for_msg, self.request_fds.len());
        } else {
            assert_eq!(self.request_tail, 0);
            assert!(cur_fd_for_msg <= self.request_fds.len());
        }
        let send_len = buf.len() - self.request_head.len();
        let size = mem::size_of::<CrossDomainSendReceive<()>>() + send_len;
        ring_msg.opaque_data_size = send_len as u32;
        ring_msg.hdr.cmd_size = size as u16;
        ring_msg.num_identifiers = cur_fd_for_msg as u32;
        let mut gem_handles = Vec::with_capacity(cur_fd_for_msg);
        let fds: Vec<OwnedFd> = self.request_fds.drain(..cur_fd_for_msg).collect();
        for (i, fd) in fds.into_iter().enumerate() {
            let filename = readlink(format!("/proc/self/fd/{}", fd.as_raw_fd()).as_str())?;
            let filename = filename.to_string_lossy();
            if filename.starts_with("/dmabuf:") {
                let gh = self.vgpu_id_from_prime(&mut ring_msg, i, &fd_xids, fd)?;
                gem_handles.push(gh);
                continue;
            }
            let creds = getsockopt(&self.socket.as_fd(), PeerCredentials)?;
            self.create_cross_vm_futex(&mut ring_msg, i, fd, &fd_xids, creds.pid(), filename)?;
        }
        self.gpu_ctx.submit_cmd(&ring_msg, size, None, None)?;
        for gem_handle in gem_handles {
            unsafe {
                let close = DrmGemClose::new(gem_handle);
                drm_gem_close(self.gpu_ctx.fd.as_raw_fd() as c_int, &close)?;
            }
        }
        for xid in fences_to_destroy {
            self.futex_watchers.remove(&xid).unwrap();
            let ft_destroy_msg_size = mem::size_of::<CrossDomainFutexDestroy>();
            let ft_msg = CrossDomainFutexDestroy {
                hdr: CrossDomainHeader::new(
                    CROSS_DOMAIN_CMD_FUTEX_DESTROY,
                    ft_destroy_msg_size as u16,
                ),
                id: xid,
                pad: 0,
            };
            self.gpu_ctx
                .submit_cmd(&ft_msg, ft_destroy_msg_size, None, None)?;
        }
        Ok(false)
    }
    fn vgpu_id_from_prime<T>(
        &mut self,
        ring_msg: &mut CrossDomainSendReceive<T>,
        i: usize,
        fd_xids: &[Option<u32>],
        fd: OwnedFd,
    ) -> Result<u32> {
        let mut to_handle = DrmPrimeHandle {
            fd: fd.as_raw_fd(),
            ..DrmPrimeHandle::default()
        };
        unsafe {
            drm_prime_fd_to_handle(self.gpu_ctx.fd.as_raw_fd() as c_int, &mut to_handle)?;
        }
        self.buffers_for_pixmap
            .entry(fd_xids[i].unwrap())
            .or_default()
            .push(fd);
        let mut res_info = DrmVirtgpuResourceInfo {
            bo_handle: to_handle.handle,
            ..DrmVirtgpuResourceInfo::default()
        };
        unsafe {
            drm_virtgpu_resource_info(self.gpu_ctx.fd.as_raw_fd() as c_int, &mut res_info)?;
        }
        ring_msg.identifiers[i] = res_info.res_handle;
        ring_msg.identifier_types[i] = CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB;
        Ok(to_handle.handle)
    }

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
    fn create_cross_vm_futex<T>(
        &mut self,
        ring_msg: &mut CrossDomainSendReceive<T>,
        i: usize,
        memfd: OwnedFd,
        fd_xids: &[Option<u32>],
        pid: pid_t,
        filename: Cow<'_, str>,
    ) -> Result<()> {
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
            id: fd_xids[i].unwrap(),
            fs_id: handle.fs_id,
            handle: handle.handle,
            pad: 0,
        };
        self.gpu_ctx
            .submit_cmd(&ft_msg, ft_new_msg_size, None, None)?;
        let sync_xid = fd_xids[i].unwrap();
        let fd = self.gpu_ctx.fd.as_raw_fd() as c_int;
        // TODO: do we need to wait here?
        //thread::sleep(Duration::from_millis(33));
        self.futex_watchers.insert(
            sync_xid,
            FutexWatcherThread::new(fd, sync_xid, addr, initial_value),
        );
        ring_msg.identifiers[i] = sync_xid;
        ring_msg.identifier_types[i] = CROSS_DOMAIN_ID_TYPE_SHM;
        Ok(())
    }
    fn process_vgpu(&mut self) -> Result<bool> {
        let mut evt = DrmEvent::default();
        read(self.gpu_ctx.fd.as_raw_fd(), unsafe {
            slice::from_raw_parts_mut(
                &mut evt as *mut DrmEvent as *mut u8,
                mem::size_of::<DrmEvent>(),
            )
        })?;
        assert_eq!(evt.ty, VIRTGPU_EVENT_FENCE_SIGNALED);
        let cmd = unsafe {
            (self.gpu_ctx.channel_ring.address as *const CrossDomainHeader)
                .as_ref()
                .unwrap()
                .cmd
        };
        match cmd {
            CROSS_DOMAIN_CMD_RECEIVE => {
                let recv = unsafe {
                    (self.gpu_ctx.channel_ring.address
                        as *const CrossDomainSendReceive<[u8; CROSS_DOMAIN_SR_TAIL_SIZE]>)
                        .as_ref()
                        .unwrap()
                };
                if recv.opaque_data_size == 0 {
                    return Ok(true);
                }
                self.process_receive(recv)?;
            },
            CROSS_DOMAIN_CMD_FUTEX_SIGNAL => {
                let recv = unsafe {
                    (self.gpu_ctx.channel_ring.address as *const CrossDomainFutexSignal)
                        .as_ref()
                        .unwrap()
                };
                self.process_futex_signal(recv)?;
            },
            a => {
                eprintln!("Received unknown cross-domain command {a}");
            },
        };
        self.gpu_ctx.poll_cmd()?;
        Ok(false)
    }
    fn process_receive(&mut self, recv: &CrossDomainSendReceive<[u8]>) -> Result<()> {
        let mut owned_fds = Vec::with_capacity(recv.num_identifiers as usize);
        for i in 0..recv.num_identifiers as usize {
            assert_eq!(recv.identifier_types[i], CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB);
            let mut create_blob = DrmVirtgpuResourceCreateBlob {
                blob_mem: VIRTGPU_BLOB_MEM_HOST3D,
                size: recv.identifier_sizes[i] as u64,
                blob_id: recv.identifiers[i] as u64,
                blob_flags: VIRTGPU_BLOB_FLAG_USE_MAPPABLE | VIRTGPU_BLOB_FLAG_USE_SHAREABLE,
                ..DrmVirtgpuResourceCreateBlob::default()
            };
            unsafe {
                drm_virtgpu_resource_create_blob(
                    self.gpu_ctx.fd.as_raw_fd() as c_int,
                    &mut create_blob,
                )?;
            }
            let mut to_fd = DrmPrimeHandle {
                handle: create_blob.bo_handle,
                flags: O_RDWR as u32,
                fd: -1,
            };
            unsafe {
                drm_prime_handle_to_fd(self.gpu_ctx.fd.as_raw_fd() as c_int, &mut to_fd)?;
                let close = DrmGemClose::new(create_blob.bo_handle);
                drm_gem_close(self.gpu_ctx.fd.as_raw_fd() as c_int, &close)?;
            }
            unsafe { owned_fds.push(OwnedFd::from_raw_fd(to_fd.fd)) }
        }
        let data = &recv.data[..(recv.opaque_data_size as usize)];
        self.debug_loop.loop_remote(data);
        if !self.got_first_resp {
            self.got_first_resp = true;
            self.reply_tail = u16::from_ne_bytes(data[6..8].try_into().unwrap()) as usize * 4 + 8;
        }
        let data = if self.reply_tail > 0 {
            assert!(self.reply_head.is_empty());
            let block = self.reply_tail.min(data.len());
            let (block_data, data) = data.split_at(block);
            // If we have a reply tail, we need to send it separately. This is to ensure
            // that no fds are attached to it, since libxcb cannot handle fds not
            // attached to a packet header.
            self.send_queue.push_back(SendPacket {
                data: block_data.into(),
                fds: Vec::new(),
            });

            self.reply_tail -= block;
            data
        } else {
            data
        };
        assert!(self.reply_tail == 0 || data.is_empty());
        if data.is_empty() {
            assert!(owned_fds.is_empty());
            return Ok(());
        }

        let data = if self.reply_head.is_empty() {
            data.to_vec()
        } else {
            let mut new_data = core::mem::take(&mut self.reply_head);
            new_data.extend_from_slice(data);
            new_data
        };

        let mut ptr = 0;
        while ptr < data.len() {
            if data.len() - ptr < 32 {
                eprintln!(
                    "X11 message truncated (expected at least 32 bytes, got {}:{} = {})",
                    ptr,
                    data.len(),
                    data.len() - ptr
                );
                break;
            }
            let seq_no = u16::from_ne_bytes(data[(ptr + 2)..(ptr + 4)].try_into().unwrap());
            let is_reply = data[ptr] == X11_REPLY;
            let is_generic = data[ptr] == X11_GENERIC_EVENT;
            let len = if is_reply || is_generic {
                u32::from_ne_bytes(data[(ptr + 4)..(ptr + 8)].try_into().unwrap()) as usize * 4
            } else {
                0
            } + 32;
            if is_reply {
                if Some(seq_no) == self.dri3_qe_resp_seq {
                    self.dri3_qe_resp_seq = None;
                    self.dri3_ext_opcode = extract_opcode_from_qe_resp(&data, ptr);
                } else if Some(seq_no) == self.sync_qe_resp_seq {
                    self.sync_qe_resp_seq = None;
                    self.sync_ext_opcode = extract_opcode_from_qe_resp(&data, ptr);
                } else if Some(seq_no) == self.present_qe_resp_seq {
                    self.present_qe_resp_seq = None;
                    self.present_ext_opcode = extract_opcode_from_qe_resp(&data, ptr);
                }
            }
            ptr += len;
        }
        let block = if ptr < data.len() {
            let (block, next_head) = data.split_at(ptr);
            self.reply_head = next_head.to_vec();
            block.to_vec()
        } else {
            self.reply_tail = ptr - data.len();
            data.to_vec()
        };
        self.send_queue.push_back(SendPacket {
            data: block,
            fds: owned_fds,
        });
        Ok(())
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

    let epoll = Epoll::new(EpollCreateFlags::empty()).unwrap();
    _ = fs::remove_file(&sock_path);
    let listen_sock = UnixListener::bind(sock_path).unwrap();
    epoll
        .add(
            &listen_sock,
            EpollEvent::new(EpollFlags::EPOLLIN, listen_sock.as_raw_fd() as u64),
        )
        .unwrap();
    let mut client_sock = HashMap::<u64, Rc<RefCell<Client>>>::new();
    let mut client_vgpu = HashMap::<u64, Rc<RefCell<Client>>>::new();
    loop {
        let mut evts = [EpollEvent::empty(); 16];
        let count = match epoll.wait(&mut evts, EpollTimeout::NONE) {
            Err(Errno::EINTR) | Ok(0) => continue,
            a => a.unwrap(),
        };
        for evt in &evts[..count.min(evts.len())] {
            let fd = evt.data();
            let events = evt.events();
            if fd == listen_sock.as_raw_fd() as u64 {
                let res = listen_sock.accept();
                if res.is_err() {
                    eprintln!(
                        "Failed to accept a connection, error: {:?}",
                        res.unwrap_err()
                    );
                    continue;
                }
                let stream = res.unwrap().0;
                stream.set_nonblocking(true).unwrap();
                let client = Rc::new(RefCell::new(Client::new(stream).unwrap()));
                client_sock.insert(client.borrow().socket.as_raw_fd() as u64, client.clone());
                epoll
                    .add(
                        &client.borrow().socket,
                        EpollEvent::new(
                            EpollFlags::EPOLLIN,
                            client.borrow().socket.as_raw_fd() as u64,
                        ),
                    )
                    .unwrap();
                client_vgpu.insert(
                    client.borrow().gpu_ctx.fd.as_raw_fd() as u64,
                    client.clone(),
                );
                epoll
                    .add(
                        &client.borrow().gpu_ctx.fd,
                        EpollEvent::new(
                            EpollFlags::EPOLLIN,
                            client.borrow().gpu_ctx.fd.as_raw_fd() as u64,
                        ),
                    )
                    .unwrap();
            } else if let Some(client) = client_sock.get_mut(&fd) {
                let event = client
                    .borrow_mut()
                    .process_socket(events)
                    .map_err(|e| {
                        eprintln!("Client {fd} disconnected with error: {e:?}");
                        e
                    })
                    .unwrap_or(ClientEvent::Close);
                match event {
                    ClientEvent::None => (),
                    ClientEvent::StartSend => {
                        epoll
                            .modify(
                                &client.borrow().socket,
                                &mut EpollEvent::new(
                                    EpollFlags::EPOLLOUT | EpollFlags::EPOLLIN,
                                    client.borrow().socket.as_raw_fd() as u64,
                                ),
                            )
                            .unwrap();
                    },
                    ClientEvent::StopSend => {
                        epoll
                            .modify(
                                &client.borrow().socket,
                                &mut EpollEvent::new(
                                    EpollFlags::EPOLLIN,
                                    client.borrow().socket.as_raw_fd() as u64,
                                ),
                            )
                            .unwrap();
                    },
                    ClientEvent::Close => {
                        let client = client.borrow();
                        let gpu_fd = client.gpu_ctx.fd.as_fd();
                        epoll.delete(gpu_fd).unwrap();
                        epoll.delete(&client.socket).unwrap();
                        let gpu_fd = gpu_fd.as_raw_fd() as u64;
                        drop(client);
                        client_vgpu.remove(&gpu_fd).unwrap();
                        client_sock.remove(&fd).unwrap();
                    },
                }
            } else if let Some(client) = client_vgpu.get_mut(&fd) {
                let queue_empty = client.borrow().send_queue.is_empty();
                let close = client
                    .borrow_mut()
                    .process_vgpu()
                    .map_err(|e| {
                        eprintln!("Server {fd} disconnected with error: {e:?}");
                        e
                    })
                    .unwrap_or(true);
                if close {
                    let client = client.borrow();
                    let gpu_fd = client.gpu_ctx.fd.as_fd();
                    epoll.delete(gpu_fd).unwrap();
                    let client_fd = client.socket.as_raw_fd() as u64;
                    epoll.delete(&client.socket).unwrap();
                    drop(client);
                    client_vgpu.remove(&fd).unwrap();
                    client_sock.remove(&client_fd).unwrap();
                } else if queue_empty && !client.borrow().send_queue.is_empty() {
                    epoll
                        .modify(
                            &client.borrow().socket,
                            &mut EpollEvent::new(
                                EpollFlags::EPOLLOUT | EpollFlags::EPOLLIN,
                                client.borrow().socket.as_raw_fd() as u64,
                            ),
                        )
                        .unwrap();
                }
            }
        }
    }
}
