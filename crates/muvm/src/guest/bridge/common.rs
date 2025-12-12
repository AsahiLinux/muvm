use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::ptr::NonNull;
use std::rc::{Rc, Weak};
use std::{env, fs, mem, slice, thread};

use anyhow::Result;
use log::debug;
use nix::errno::Errno;
use nix::libc::{c_int, c_void, off_t, O_RDWR};
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags, RecvMsg};
use nix::unistd::read;
use nix::{cmsg_space, ioctl_readwrite, ioctl_write_ptr};

pub const PAGE_SIZE: usize = 4096;

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
        Self {
            handle,
            ..Default::default()
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
pub struct CrossDomainHeader {
    pub cmd: u8,
    pub fence_ctx_idx: u8,
    pub cmd_size: u16,
    pub pad: u32,
}

impl CrossDomainHeader {
    pub fn new(cmd: u8, cmd_size: u16) -> CrossDomainHeader {
        Self {
            cmd,
            cmd_size,
            ..Default::default()
        }
    }
}

const CROSS_DOMAIN_CMD_INIT: u8 = 1;
const CROSS_DOMAIN_CMD_POLL: u8 = 3;
const CROSS_DOMAIN_PROTOCOL_VERSION: u32 = 1;
#[repr(C)]
#[derive(Default)]
struct CrossDomainInit {
    hdr: CrossDomainHeader,
    query_ring_id: u32,
    channel_ring_id: u32,
    channel_type: u32,
    protocol_version: u32,
}

#[repr(C)]
#[derive(Default)]
struct CrossDomainPoll {
    hdr: CrossDomainHeader,
    pad: u64,
}

impl CrossDomainPoll {
    fn new() -> CrossDomainPoll {
        Self {
            hdr: CrossDomainHeader::new(
                CROSS_DOMAIN_CMD_POLL,
                mem::size_of::<CrossDomainPoll>() as u16,
            ),
            ..Default::default()
        }
    }
}

const CROSS_DOMAIN_MAX_IDENTIFIERS: usize = 28;
const CROSS_DOMAIN_CMD_SEND: u8 = 4;
const CROSS_DOMAIN_CMD_RECEIVE: u8 = 5;

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

pub struct GpuRing {
    handle: u32,
    res_id: u32,
    pub address: *mut c_void,
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
        // SAFETY: `create_blob` is initialized correctly, and we own it
        unsafe {
            drm_virtgpu_resource_create_blob(fd.as_raw_fd() as c_int, &mut create_blob)?;
        }
        let mut map = DrmVirtgpuMap {
            handle: create_blob.bo_handle,
            ..DrmVirtgpuMap::default()
        };
        // SAFETY: `map` is initialized correctly, and we own it
        unsafe {
            drm_virtgpu_map(fd.as_raw_fd() as c_int, &mut map)?;
        }
        // SAFETY: we are not overmapping anyting, and we will own the ring
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
        // SAFETY: self.address was got from mmap, we own self.fd
        unsafe {
            munmap(NonNull::new(self.address).unwrap(), PAGE_SIZE).unwrap();
            let close = DrmGemClose::new(self.handle);
            drm_gem_close(self.fd.as_raw_fd() as c_int, &close).unwrap();
        }
    }
}

pub struct Context {
    pub fd: OwnedFd,
    pub channel_ring: GpuRing,
    query_ring: GpuRing,
}

impl Context {
    fn new(channel_type: u32) -> Result<Context> {
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
        // SAFETY: `init` and `parms` outlive this call
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
            channel_type,
            protocol_version: CROSS_DOMAIN_PROTOCOL_VERSION,
        };
        this.submit_cmd(&init_cmd, mem::size_of::<CrossDomainInit>(), None)?;
        this.poll_cmd()?;
        Ok(this)
    }

    pub fn submit_cmd<T>(&self, cmd: &T, cmd_size: usize, ring_idx: Option<u32>) -> Result<()> {
        submit_cmd_raw(self.fd.as_raw_fd() as c_int, cmd, cmd_size, ring_idx)
    }

    fn poll_cmd(&self) -> Result<()> {
        let cmd = CrossDomainPoll::new();
        self.submit_cmd(
            &cmd,
            mem::size_of::<CrossDomainPoll>(),
            Some(CROSS_DOMAIN_CHANNEL_RING),
        )
    }
}

pub fn submit_cmd_raw<T>(fd: c_int, cmd: &T, cmd_size: usize, ring_idx: Option<u32>) -> Result<()> {
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
    // SAFETY: `exec` and `cmd` outlive the call, and it does not modify `cmd`
    unsafe {
        drm_virtgpu_execbuffer(fd, &mut exec)?;
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

pub struct SendPacket {
    pub data: Vec<u8>,
    pub fds: Vec<OwnedFd>,
}

pub trait MessageResourceFinalizer {
    type Handler: ProtocolHandler;
    fn finalize(self, client: &mut Client<Self::Handler>) -> Result<()>;
}

#[derive(Debug)]
pub struct CrossDomainResource {
    pub identifier: u32,
    pub identifier_type: u32,
    pub identifier_size: u32,
}

pub enum StreamSendResult<MRF: MessageResourceFinalizer> {
    WantMore,
    Processed {
        consumed_bytes: usize,
        resources: Vec<CrossDomainResource>,
        finalizers: Vec<MRF>,
    },
}

pub enum StreamRecvResult {
    WantMore,
    Processed {
        consumed_bytes: usize,
        fds: Vec<OwnedFd>,
    },
}

pub trait ProtocolHandler: Sized {
    type ResourceFinalizer: MessageResourceFinalizer<Handler = Self>;

    const CHANNEL_TYPE: u32;

    fn new() -> Self;

    fn process_recv_stream(
        this: &mut Client<Self>,
        data: &[u8],
        resources: &mut VecDeque<CrossDomainResource>,
    ) -> Result<StreamRecvResult>;

    fn process_send_stream(
        this: &mut Client<Self>,
        data: &mut [u8],
    ) -> Result<StreamSendResult<Self::ResourceFinalizer>>;

    fn process_vgpu_extra(this: &mut Client<Self>, cmd: u8) -> Result<()>;

    fn process_fd_extra(this: &mut Client<Self>, fd: u64, events: EpollFlags) -> Result<()>;
}

pub struct Client<'a, P: ProtocolHandler> {
    // protocol_handler must be dropped before gpu_ctx, so it goes first
    pub protocol_handler: P,
    pub gpu_ctx: Context,
    pub socket: UnixStream,
    reply_tail: usize,
    reply_head: Vec<u8>,
    request_tail: usize,
    request_head: Vec<u8>,
    pub request_fds: Vec<OwnedFd>,
    debug_loop: DebugLoop,
    pub send_queue: VecDeque<SendPacket>,
    pub sub_poll: SubPoll<'a, P>,
}

#[derive(Debug)]
enum ClientEvent {
    None,
    StartSend,
    StopSend,
    Close,
}

pub struct GemHandleFinalizer(u32);

impl GemHandleFinalizer {
    pub fn finalize<T: ProtocolHandler>(self, client: &mut Client<T>) -> Result<()> {
        // SAFETY: we own self.0
        unsafe {
            let close = DrmGemClose::new(self.0);
            drm_gem_close(client.gpu_ctx.fd.as_raw_fd() as c_int, &close)?;
        }
        Ok(())
    }
}

impl<'a, P: ProtocolHandler> Client<'a, P> {
    fn new(
        socket: UnixStream,
        protocol_handler: P,
        sub_poll: SubPoll<'a, P>,
    ) -> Result<Rc<RefCell<Client<'a, P>>>> {
        let this = Rc::new(RefCell::new(Client {
            socket,
            protocol_handler,
            gpu_ctx: Context::new(P::CHANNEL_TYPE)?,
            reply_tail: 0,
            reply_head: Vec::new(),
            request_tail: 0,
            request_head: Vec::new(),
            request_fds: Vec::new(),
            debug_loop: DebugLoop::new(),
            send_queue: VecDeque::new(),
            sub_poll,
        }));
        {
            let mut borrow = this.borrow_mut();
            let borrow = &mut *borrow;
            borrow.sub_poll.my_client = Rc::downgrade(&this);
            borrow
                .sub_poll
                .add(borrow.socket.as_fd(), EpollFlags::EPOLLIN);
            borrow
                .sub_poll
                .add(borrow.gpu_ctx.fd.as_fd(), EpollFlags::EPOLLIN);
        }
        Ok(this)
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
                        // SAFETY: `fd` is a valid unowned fd we got from recvmsg
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
        let mut resources = Vec::new();
        let mut finalizers = Vec::new();
        if self.request_tail > 0 {
            assert!(self.request_fds.is_empty());
            self.request_tail -= buf.len();
        } else {
            let mut ptr = 0;
            while ptr < buf.len() {
                match P::process_send_stream(self, &mut buf[ptr..])? {
                    StreamSendResult::WantMore => break,
                    StreamSendResult::Processed {
                        resources: rs,
                        finalizers: fns,
                        consumed_bytes: msg_size,
                    } => {
                        ptr += msg_size;
                        resources.extend(rs);
                        finalizers.extend(fns);
                    },
                }
            }
            if ptr < buf.len() {
                self.request_head = buf[ptr..].to_vec();
            } else {
                self.request_tail = ptr - buf.len();
            }
        }
        if !self.request_head.is_empty() {
            assert_eq!(self.request_tail, 0);
        }
        let send_len = buf.len() - self.request_head.len();
        let size = mem::size_of::<CrossDomainSendReceive<()>>() + send_len;
        ring_msg.opaque_data_size = send_len as u32;
        ring_msg.hdr.cmd_size = size as u16;
        ring_msg.num_identifiers = resources.len() as u32;
        for (i, res) in resources.into_iter().enumerate() {
            ring_msg.identifiers[i] = res.identifier;
            ring_msg.identifier_types[i] = res.identifier_type;
            ring_msg.identifier_sizes[i] = res.identifier_size;
        }
        self.gpu_ctx.submit_cmd(&ring_msg, size, None)?;
        for fin in finalizers {
            fin.finalize(self)?;
        }
        Ok(false)
    }

    pub fn vgpu_id_from_prime(
        &mut self,
        fd: OwnedFd,
    ) -> Result<(CrossDomainResource, GemHandleFinalizer)> {
        let mut to_handle = DrmPrimeHandle {
            fd: fd.as_raw_fd(),
            ..DrmPrimeHandle::default()
        };
        // SAFETY: `to_handle` outlives the call, and is initialized
        unsafe {
            drm_prime_fd_to_handle(self.gpu_ctx.fd.as_raw_fd() as c_int, &mut to_handle)?;
        }
        let mut res_info = DrmVirtgpuResourceInfo {
            bo_handle: to_handle.handle,
            ..DrmVirtgpuResourceInfo::default()
        };
        // SAFETY: `res_info` outlives the call, and is initialized
        unsafe {
            drm_virtgpu_resource_info(self.gpu_ctx.fd.as_raw_fd() as c_int, &mut res_info)?;
        }
        Ok((
            CrossDomainResource {
                identifier: res_info.res_handle,
                identifier_type: CROSS_DOMAIN_ID_TYPE_VIRTGPU_BLOB,
                identifier_size: 0,
            },
            GemHandleFinalizer(to_handle.handle),
        ))
    }

    fn process_vgpu(&mut self) -> Result<bool> {
        let mut evt = DrmEvent::default();
        // SAFETY: `read` will return a valid DrmEvent
        read(self.gpu_ctx.fd.as_fd(), unsafe {
            slice::from_raw_parts_mut(
                &mut evt as *mut DrmEvent as *mut u8,
                mem::size_of::<DrmEvent>(),
            )
        })?;
        assert_eq!(evt.ty, VIRTGPU_EVENT_FENCE_SIGNALED);
        // SAFETY: vmm will put a valid cross domain message at that address
        let cmd = unsafe {
            (self.gpu_ctx.channel_ring.address as *const CrossDomainHeader)
                .as_ref()
                .unwrap()
                .cmd
        };
        match cmd {
            CROSS_DOMAIN_CMD_RECEIVE => {
                // SAFETY: vmm will put a valid cross domain message at that address
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
            cmd => P::process_vgpu_extra(self, cmd)?,
        };
        self.gpu_ctx.poll_cmd()?;
        Ok(false)
    }

    pub fn virtgpu_id_to_prime(&mut self, rsc: CrossDomainResource) -> Result<OwnedFd> {
        let mut create_blob = DrmVirtgpuResourceCreateBlob {
            blob_mem: VIRTGPU_BLOB_MEM_HOST3D,
            size: rsc.identifier_size as u64,
            blob_id: rsc.identifier as u64,
            blob_flags: VIRTGPU_BLOB_FLAG_USE_MAPPABLE | VIRTGPU_BLOB_FLAG_USE_SHAREABLE,
            ..DrmVirtgpuResourceCreateBlob::default()
        };
        // SAFETY: `create_blob` outlives the call
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
        // SAFETY: `to_fd` and `close` outlive the respective calls
        unsafe {
            drm_prime_handle_to_fd(self.gpu_ctx.fd.as_raw_fd() as c_int, &mut to_fd)?;
            let close = DrmGemClose::new(create_blob.bo_handle);
            drm_gem_close(self.gpu_ctx.fd.as_raw_fd() as c_int, &close)?;
        }
        // SAFETY: `to_fd.fd` contains a valid fd
        Ok(unsafe { OwnedFd::from_raw_fd(to_fd.fd) })
    }

    fn process_receive(&mut self, recv: &CrossDomainSendReceive<[u8]>) -> Result<()> {
        let mut identifiers = VecDeque::with_capacity(recv.num_identifiers as usize);
        for i in 0..recv.num_identifiers as usize {
            identifiers.push_back(CrossDomainResource {
                identifier: recv.identifiers[i],
                identifier_size: recv.identifier_sizes[i],
                identifier_type: recv.identifier_types[i],
            });
        }
        let data = &recv.data[..(recv.opaque_data_size as usize)];
        self.debug_loop.loop_remote(data);
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
            assert_eq!(recv.num_identifiers, 0);
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
        let mut owned_fds = Vec::new();
        while ptr < data.len() {
            match P::process_recv_stream(self, &data[ptr..], &mut identifiers)? {
                StreamRecvResult::Processed {
                    consumed_bytes,
                    fds,
                } => {
                    ptr += consumed_bytes;
                    owned_fds.extend(fds);
                },
                StreamRecvResult::WantMore => break,
            }
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

    fn process_epoll(&mut self, fd: u64, events: EpollFlags) {
        if fd == self.socket.as_raw_fd() as u64 {
            let event = self
                .process_socket(events)
                .map_err(|err| {
                    if let Some(errno) = err.downcast_ref::<Errno>() {
                        if errno == &Errno::ECONNRESET {
                            debug!("Client {fd} disconnected with error: {err:?}");
                            return err;
                        }
                    }
                    eprintln!("Client {fd} disconnected with error: {err:?}");
                    err
                })
                .unwrap_or(ClientEvent::Close);
            match event {
                ClientEvent::None => {},
                ClientEvent::StartSend => {
                    self.sub_poll.modify(
                        self.socket.as_fd(),
                        EpollFlags::EPOLLOUT | EpollFlags::EPOLLIN,
                    );
                },
                ClientEvent::StopSend => {
                    self.sub_poll
                        .modify(self.socket.as_fd(), EpollFlags::EPOLLIN);
                },
                ClientEvent::Close => {
                    self.sub_poll.close();
                },
            }
        } else if fd == self.gpu_ctx.fd.as_raw_fd() as u64 {
            let queue_empty = self.send_queue.is_empty();
            let close = self
                .process_vgpu()
                .map_err(|e| {
                    eprintln!("Server {fd} disconnected with error: {e:?}");
                    e
                })
                .unwrap_or(true);
            if close {
                self.sub_poll.close();
            } else if queue_empty && !self.send_queue.is_empty() {
                self.sub_poll.modify(
                    self.socket.as_fd(),
                    EpollFlags::EPOLLOUT | EpollFlags::EPOLLIN,
                );
            }
        } else {
            let close = P::process_fd_extra(self, fd, events)
                .map_err(|e| {
                    let srv_id = self.gpu_ctx.fd.as_raw_fd() as u64;
                    eprintln!("Server {srv_id} disconnected with error: {e:?}");
                    e
                })
                .is_err();
            if close {
                self.sub_poll.close();
            }
        }
    }
}

type ClientMap<'a, T> = Rc<RefCell<HashMap<u64, Rc<RefCell<Client<'a, T>>>>>>;

pub struct SubPoll<'a, T: ProtocolHandler> {
    epoll: &'a Epoll,
    all_clients: ClientMap<'a, T>,
    my_client: Weak<RefCell<Client<'a, T>>>,
    my_entries: HashSet<u64>,
}

impl<'a, T: ProtocolHandler> SubPoll<'a, T> {
    fn new(epoll: &'a Epoll, all_clients: ClientMap<'a, T>) -> SubPoll<'a, T> {
        SubPoll {
            epoll,
            all_clients,
            my_client: Weak::new(),
            my_entries: HashSet::new(),
        }
    }

    pub fn add(&mut self, fd: BorrowedFd, events: EpollFlags) {
        let my_client = self.my_client.upgrade().unwrap();
        let mut clients = self.all_clients.borrow_mut();
        let raw = fd.as_raw_fd() as u64;
        self.epoll.add(fd, EpollEvent::new(events, raw)).unwrap();
        clients.insert(raw, my_client.clone());
        self.my_entries.insert(raw);
    }

    pub fn modify(&mut self, fd: BorrowedFd, events: EpollFlags) {
        self.epoll
            .modify(fd, &mut EpollEvent::new(events, fd.as_raw_fd() as u64))
            .unwrap();
    }

    pub fn remove(&mut self, fd: BorrowedFd) {
        let mut clients = self.all_clients.borrow_mut();
        let raw = fd.as_raw_fd() as u64;
        self.epoll.delete(fd).unwrap();
        self.my_entries.remove(&raw);
        clients.remove(&raw);
    }

    fn close(&mut self) {
        let mut clients = self.all_clients.borrow_mut();
        for entry in self.my_entries.drain() {
            clients.remove(&entry);
        }
        // No need to remove from epoll, fds get automatically removed on close.
    }
}

pub fn bridge_loop_with_listenfd<T: ProtocolHandler>(fallback_sock_path: impl Fn() -> String) {
    if let Some(listen_sock) = listenfd::ListenFd::from_env()
        .take_unix_listener(0)
        .unwrap()
    {
        bridge_loop_sock::<T>(listen_sock)
    } else {
        bridge_loop::<T>(&fallback_sock_path())
    }
}

pub fn bridge_loop<T: ProtocolHandler>(sock_path: &str) {
    _ = fs::remove_file(sock_path);
    bridge_loop_sock::<T>(UnixListener::bind(sock_path).unwrap());
}

pub fn bridge_loop_sock<T: ProtocolHandler>(listen_sock: UnixListener) {
    let epoll = Epoll::new(EpollCreateFlags::empty()).unwrap();
    epoll
        .add(
            &listen_sock,
            EpollEvent::new(EpollFlags::EPOLLIN, listen_sock.as_raw_fd() as u64),
        )
        .unwrap();
    let clients = Rc::new(RefCell::new(HashMap::<u64, Rc<RefCell<Client<T>>>>::new()));
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
                if let Err(res) = res {
                    eprintln!("Failed to accept a connection, error: {res:?}");
                    continue;
                }
                let stream = res.unwrap().0;
                stream.set_nonblocking(true).unwrap();
                let sub_poll = SubPoll::new(&epoll, clients.clone());
                Client::new(stream, T::new(), sub_poll).unwrap();
                continue;
            }
            let client = {
                // Ensure the borrow on `clients` is dropped when we are calling `process_epoll`
                clients.borrow().get(&fd).cloned()
            };
            if let Some(client) = client {
                client.borrow_mut().process_epoll(fd, events);
            }
        }
    }
}
