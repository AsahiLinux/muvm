use std::collections::{HashMap, VecDeque};
use std::ffi::CStr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::{env, mem};

use anyhow::Result;
use log::debug;
use nix::errno::Errno;
use nix::sys::epoll::EpollFlags;
use nix::sys::eventfd::{EfdFlags, EventFd};

use crate::guest::bridge::common;
use crate::guest::bridge::common::{
    Client, CrossDomainHeader, CrossDomainResource, MessageResourceFinalizer, ProtocolHandler,
    StreamRecvResult, StreamSendResult,
};

const CROSS_DOMAIN_CHANNEL_TYPE_PW: u32 = 0x10;
const CROSS_DOMAIN_CMD_READ_EVENTFD_NEW: u8 = 11;
const CROSS_DOMAIN_CMD_READ: u8 = 6;
const CROSS_DOMAIN_CMD_WRITE: u8 = 7;

const SPA_TYPE_STRUCT: u32 = 14;
const SPA_TYPE_FD: u32 = 18;

const PW_OPC_CORE_CREATE_OBJECT: u8 = 6;
const PW_OPC_CORE_ADD_MEM: u8 = 6;
const PW_OPC_CLIENT_UPDATE_PROPERTIES: u8 = 2;
const PW_OPC_CLIENT_NODE_TRANSPORT: u8 = 0;
const PW_OPC_CLIENT_NODE_SET_ACTIVATION: u8 = 10;

#[repr(C)]
struct CrossDomainReadWrite<T: ?Sized> {
    hdr: CrossDomainHeader,
    identifier: u32,
    hang_up: u32,
    opaque_data_size: u32,
    pad: u32,
    data: T,
}

#[repr(C)]
struct CrossDomainReadEventfdNew {
    pub hdr: CrossDomainHeader,
    pub id: u32,
    pub pad: u32,
}

fn align_up(v: u32, a: u32) -> u32 {
    (v + a - 1) & !(a - 1)
}

fn read_u32(data: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(data[at..(at + 4)].try_into().unwrap())
}

fn read_u64(data: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(data[at..(at + 8)].try_into().unwrap())
}

#[derive(Debug)]
struct CoreCreateObject<'a> {
    obj_type: &'a CStr,
    new_id: u32,
}

impl<'a> CoreCreateObject<'a> {
    fn new(data: &'a [u8]) -> Self {
        let ty = read_u32(data, 4);
        assert_eq!(ty, SPA_TYPE_STRUCT);
        let factory_name_ptr = 8;
        let factory_name_size = read_u32(data, factory_name_ptr);
        let type_ptr = factory_name_ptr + align_up(factory_name_size + 8, 8) as usize;
        let type_size = read_u32(data, type_ptr);
        let obj_type =
            CStr::from_bytes_with_nul(&data[(type_ptr + 8)..(type_ptr + 8 + type_size as usize)])
                .unwrap();
        let version_ptr = type_ptr + align_up(type_size + 8, 8) as usize;
        let version_size = read_u32(data, version_ptr);
        let props_ptr = version_ptr + align_up(version_size + 8, 8) as usize;
        let props_size = read_u32(data, props_ptr);
        let new_id_ptr = props_ptr + align_up(props_size + 8, 8) as usize;
        let new_id = read_u32(data, new_id_ptr + 8);
        CoreCreateObject { obj_type, new_id }
    }
}

#[derive(Debug)]
struct ClientUpdateProperties<'a> {
    props: Vec<(&'a mut [u8], &'a mut [u8])>,
}

impl<'a> ClientUpdateProperties<'a> {
    fn new(mut data: &'a mut [u8]) -> Self {
        let ty = read_u32(data, 4);
        assert_eq!(ty, SPA_TYPE_STRUCT);
        let props_ptr = 8;
        let n_items_ptr = props_ptr + 8;
        let n_items_size = read_u32(data, n_items_ptr);
        let n_items = read_u32(data, n_items_ptr + 8) as usize;
        let key_ptr = n_items_ptr + align_up(n_items_size + 8, 8) as usize;
        let mut props = Vec::with_capacity(n_items);
        data = data.split_at_mut(key_ptr).1;
        for _ in 0..n_items {
            let key_size = read_u32(data, 0);
            data = data.split_at_mut(8).1;
            let (key, data2) = data.split_at_mut(key_size as usize);
            data = data2;
            let pad_size = (align_up(key_size, 8) - key_size) as usize;
            data = data.split_at_mut(pad_size).1;
            let value_size = read_u32(data, 0);
            data = data.split_at_mut(8).1;
            let (value, data2) = data.split_at_mut(value_size as usize);
            data = data2;
            let pad_size = (align_up(value_size, 8) - value_size) as usize;
            data = data.split_at_mut(pad_size).1;
            props.push((key, value));
        }
        ClientUpdateProperties { props }
    }
}

#[derive(Debug)]
struct ClientNodeTransport {
    readfd: u64,
    writefd: u64,
    // .. don't care about the remaining ones
}

impl ClientNodeTransport {
    fn new(data: &[u8]) -> Self {
        let ty = read_u32(data, 4);
        assert_eq!(ty, SPA_TYPE_STRUCT);
        let readfd_ty = read_u32(data, 12);
        assert_eq!(readfd_ty, SPA_TYPE_FD);
        let readfd = read_u64(data, 16);
        let writefd_ty = read_u32(data, 28);
        assert_eq!(writefd_ty, SPA_TYPE_FD);
        let writefd = read_u64(data, 32);
        ClientNodeTransport { readfd, writefd }
    }
}

struct PipeWireHeader {
    id: u32,
    opcode: u8,
    size: usize,
    num_fd: usize,
}

impl PipeWireHeader {
    const SIZE: usize = 16;
    fn from_stream(data: &[u8]) -> PipeWireHeader {
        let id = read_u32(data, 0);
        let opc_len_word = read_u32(data, 4) as usize;
        let opcode = (opc_len_word >> 24) as u8;
        let size = (opc_len_word & 0xFFFFFF) + 16;
        let num_fd = read_u32(data, 12) as usize;
        PipeWireHeader {
            id,
            opcode,
            size,
            num_fd,
        }
    }
}

struct PipeWireResourceFinalizer;

impl MessageResourceFinalizer for PipeWireResourceFinalizer {
    type Handler = PipeWireProtocolHandler;

    fn finalize(self, _: &mut Client<Self::Handler>) -> Result<()> {
        unreachable!()
    }
}

struct CrossDomainEventFd {
    event_fd: EventFd,
    resource: u32,
}

struct ClientNodeData {
    host_to_guest: Vec<u32>,
    guest_to_host: Vec<u64>,
}

impl ClientNodeData {
    fn new() -> Self {
        ClientNodeData {
            host_to_guest: Vec::new(),
            guest_to_host: Vec::new(),
        }
    }
}

struct PipeWireProtocolHandler {
    client_nodes: HashMap<u32, ClientNodeData>,
    guest_to_host_eventfds: HashMap<u64, CrossDomainEventFd>,
    host_to_guest_eventfds: HashMap<u32, CrossDomainEventFd>,
}

impl PipeWireProtocolHandler {
    fn create_guest_to_host_eventfd(
        this: &mut Client<Self>,
        node_id: u32,
        resource: CrossDomainResource,
    ) -> Result<OwnedFd> {
        let efd = EventFd::from_flags(EfdFlags::EFD_NONBLOCK)?;
        let ofd = efd.as_fd().try_clone_to_owned()?;
        this.sub_poll.add(efd.as_fd(), EpollFlags::EPOLLIN);
        let raw = efd.as_raw_fd() as u64;
        this.protocol_handler.guest_to_host_eventfds.insert(
            raw,
            CrossDomainEventFd {
                event_fd: efd,
                resource: resource.identifier,
            },
        );
        this.protocol_handler
            .client_nodes
            .get_mut(&node_id)
            .unwrap()
            .guest_to_host
            .push(raw);
        Ok(ofd)
    }

    fn create_host_to_guest_eventfd(
        this: &mut Client<Self>,
        node_id: u32,
        resource: CrossDomainResource,
    ) -> Result<OwnedFd> {
        let efd = EventFd::from_flags(EfdFlags::EFD_NONBLOCK)?;
        let ofd = efd.as_fd().try_clone_to_owned()?;
        let msg_size = mem::size_of::<CrossDomainReadEventfdNew>();
        let msg = CrossDomainReadEventfdNew {
            hdr: CrossDomainHeader::new(CROSS_DOMAIN_CMD_READ_EVENTFD_NEW, msg_size as u16),
            id: resource.identifier,
            pad: 0,
        };
        this.protocol_handler
            .client_nodes
            .get_mut(&node_id)
            .unwrap()
            .host_to_guest
            .push(resource.identifier);
        this.gpu_ctx.submit_cmd(&msg, msg_size, None)?;
        this.protocol_handler.host_to_guest_eventfds.insert(
            resource.identifier,
            CrossDomainEventFd {
                event_fd: efd,
                resource: resource.identifier,
            },
        );
        Ok(ofd)
    }
}

impl ProtocolHandler for PipeWireProtocolHandler {
    type ResourceFinalizer = PipeWireResourceFinalizer;

    const CHANNEL_TYPE: u32 = CROSS_DOMAIN_CHANNEL_TYPE_PW;

    fn new() -> Self {
        PipeWireProtocolHandler {
            client_nodes: HashMap::new(),
            guest_to_host_eventfds: HashMap::new(),
            host_to_guest_eventfds: HashMap::new(),
        }
    }

    fn process_recv_stream(
        this: &mut Client<Self>,
        data: &[u8],
        resources: &mut VecDeque<CrossDomainResource>,
    ) -> Result<StreamRecvResult> {
        if data.len() < PipeWireHeader::SIZE {
            debug!(
                "Pipewire message truncated (expected at least 16 bytes, got {})",
                data.len(),
            );
            return Ok(StreamRecvResult::WantMore);
        }
        let hdr = PipeWireHeader::from_stream(data);
        let mut fds = Vec::with_capacity(hdr.num_fd);
        if hdr.num_fd != 0 {
            if hdr.id == 0 && hdr.opcode == PW_OPC_CORE_ADD_MEM {
                let rsc = resources.pop_front().ok_or(Errno::EIO)?;
                fds.push(this.virtgpu_id_to_prime(rsc)?);
            } else if this.protocol_handler.client_nodes.contains_key(&hdr.id) {
                if hdr.opcode == PW_OPC_CLIENT_NODE_SET_ACTIVATION {
                    let rsc = resources.pop_front().ok_or(Errno::EIO)?;
                    fds.push(Self::create_guest_to_host_eventfd(this, hdr.id, rsc)?);
                } else if hdr.opcode == PW_OPC_CLIENT_NODE_TRANSPORT {
                    let msg = ClientNodeTransport::new(&data[PipeWireHeader::SIZE..]);
                    // We need to take elements out by index without shifting the indices.
                    let mut resources: Vec<_> = resources.drain(..hdr.num_fd).map(Some).collect();
                    let writefd_rsc = resources.get_mut(msg.writefd as usize).ok_or(Errno::EIO)?;
                    fds.push(Self::create_guest_to_host_eventfd(
                        this,
                        hdr.id,
                        writefd_rsc.take().ok_or(Errno::EIO)?,
                    )?);
                    let readfd_rsc = resources.get_mut(msg.readfd as usize).ok_or(Errno::EIO)?;
                    fds.push(Self::create_host_to_guest_eventfd(
                        this,
                        hdr.id,
                        readfd_rsc.take().ok_or(Errno::EIO)?,
                    )?);
                } else {
                    unimplemented!()
                }
            } else {
                unimplemented!();
            }
        };
        Ok(StreamRecvResult::Processed {
            consumed_bytes: hdr.size,
            fds,
        })
    }

    fn process_send_stream(
        this: &mut Client<Self>,
        data: &mut [u8],
    ) -> Result<StreamSendResult<Self::ResourceFinalizer>> {
        if data.len() < PipeWireHeader::SIZE {
            debug!(
                "Pipewire message truncated (expected at least 16 bytes, got {})",
                data.len(),
            );
            return Ok(StreamSendResult::WantMore);
        }
        let hdr = PipeWireHeader::from_stream(data);
        if hdr.id == 1 && hdr.opcode == PW_OPC_CLIENT_UPDATE_PROPERTIES {
            let msg = ClientUpdateProperties::new(&mut data[PipeWireHeader::SIZE..]);
            for (k, _) in msg.props {
                if CStr::from_bytes_with_nul(k).unwrap() == c"pipewire.access.portal.app_id" {
                    k.copy_from_slice(c"pipewire.access.muvm00.app_id".to_bytes_with_nul());
                }
            }
        }
        if hdr.id == 0 && hdr.opcode == PW_OPC_CORE_CREATE_OBJECT {
            let msg = CoreCreateObject::new(&data[PipeWireHeader::SIZE..]);
            if msg.obj_type == c"PipeWire:Interface:ClientNode" {
                this.protocol_handler
                    .client_nodes
                    .insert(msg.new_id, ClientNodeData::new());
            }
        }
        if hdr.num_fd != 0 {
            unimplemented!();
        };
        Ok(StreamSendResult::Processed {
            consumed_bytes: hdr.size,
            resources: Vec::new(),
            finalizers: Vec::new(),
        })
    }

    fn process_vgpu_extra(this: &mut Client<Self>, cmd: u8) -> Result<()> {
        if cmd != CROSS_DOMAIN_CMD_READ {
            return Err(Errno::EINVAL.into());
        }
        // SAFETY: vmm will put a valid cross domain message at that address
        let recv = unsafe {
            (this.gpu_ctx.channel_ring.address
                as *const CrossDomainReadWrite<[u8; mem::size_of::<u64>()]>)
                .as_ref()
                .unwrap()
        };
        if (recv.opaque_data_size as usize) < mem::size_of::<u64>() {
            return Err(Errno::EINVAL.into());
        }
        if let Some(efd) = this
            .protocol_handler
            .host_to_guest_eventfds
            .get(&recv.identifier)
        {
            efd.event_fd.write(u64::from_ne_bytes(recv.data))?;
            Ok(())
        } else {
            Err(Errno::ENOENT.into())
        }
    }

    fn process_fd_extra(this: &mut Client<Self>, fd: u64, _: EpollFlags) -> Result<()> {
        let efd = this
            .protocol_handler
            .guest_to_host_eventfds
            .get(&fd)
            .ok_or(Errno::ENOENT)?;
        let msg_size = mem::size_of::<CrossDomainReadWrite<[u8; mem::size_of::<u64>()]>>();
        let val = efd.event_fd.read()?;
        let msg = CrossDomainReadWrite {
            hdr: CrossDomainHeader::new(CROSS_DOMAIN_CMD_WRITE, msg_size as u16),
            identifier: efd.resource,
            hang_up: 0,
            opaque_data_size: mem::size_of::<u64>() as u32,
            pad: 0,
            data: val.to_ne_bytes(),
        };
        this.gpu_ctx.submit_cmd(&msg, msg_size, None)
    }
}

pub fn start_pwbridge() {
    let sock_path = format!("{}/pipewire-0", env::var("XDG_RUNTIME_DIR").unwrap());

    common::bridge_loop::<PipeWireProtocolHandler>(&sock_path)
}
