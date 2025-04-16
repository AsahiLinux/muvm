use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use anyhow::{Context, Result};
use neli::consts::nl::NlmF;
use neli::consts::rtnl::{
    Arphrd, Ifa, IfaF, Iff, Ifla, RtAddrFamily, RtScope, RtTable, Rta, Rtm, RtmF, Rtn, Rtprot,
};
use neli::consts::socket::NlFamily;
use neli::nl::{NlPayload, Nlmsghdr};
use neli::router::synchronous::{NlRouter, NlRouterReceiverHandle};
use neli::rtnl::{
    Ifaddrmsg, IfaddrmsgBuilder, Ifinfomsg, IfinfomsgBuilder, RtattrBuilder, Rtmsg, RtmsgBuilder,
};
use neli::types::RtBuffer;
use neli::utils::Groups;
use rustix::system::sethostname;

/// Set interface flags for eth0 (interface index 2) with a given mask
fn flags_eth0(rtnl: &NlRouter, mask: Iff, set: Iff) -> Result<()> {
    let ifinfomsg = IfinfomsgBuilder::default()
        .ifi_family(RtAddrFamily::Unspecified)
        .ifi_type(Arphrd::Ether)
        .ifi_index(2)
        .ifi_change(mask)
        .ifi_flags(set)
        .build()?;

    let _: NlRouterReceiverHandle<Rtm, Ifinfomsg> =
        rtnl.send(Rtm::Newlink, NlmF::REQUEST, NlPayload::Payload(ifinfomsg))?;

    Ok(())
}

/// Set MTU for eth0 (interface index 2)
fn mtu_eth0(rtnl: &NlRouter, mtu: u32) -> Result<()> {
    let ifinfomsg = IfinfomsgBuilder::default()
        .ifi_family(RtAddrFamily::Unspecified)
        .ifi_type(Arphrd::Ether)
        .ifi_index(2)
        .rtattrs(RtBuffer::from_iter([RtattrBuilder::default()
            .rta_type(Ifla::Mtu)
            .rta_payload(mtu)
            .build()?]))
        .build()?;

    let _: NlRouterReceiverHandle<Rtm, Ifinfomsg> =
        rtnl.send(Rtm::Newlink, NlmF::REQUEST, NlPayload::Payload(ifinfomsg))?;

    Ok(())
}

/// Add or delete IPv4 routes for eth0 (interface index 2)
fn route4_eth0(rtnl: &NlRouter, what: Rtm, gw: Ipv4Addr) -> Result<()> {
    let rtmsg = RtmsgBuilder::default()
        .rtm_family(RtAddrFamily::Inet)
        .rtm_dst_len(0)
        .rtm_src_len(0)
        .rtm_tos(0)
        .rtm_table(RtTable::Main)
        .rtm_protocol(Rtprot::Boot)
        .rtm_scope(RtScope::Universe)
        .rtm_type(Rtn::Unicast)
        .rtm_flags(RtmF::empty())
        .rtattrs(RtBuffer::from_iter([
            RtattrBuilder::default()
                .rta_type(Rta::Oif)
                .rta_payload(2)
                .build()?,
            RtattrBuilder::default()
                .rta_type(Rta::Dst)
                .rta_payload(Ipv4Addr::UNSPECIFIED.octets().to_vec())
                .build()?,
            RtattrBuilder::default()
                .rta_type(Rta::Gateway)
                .rta_payload(gw.octets().to_vec())
                .build()?,
        ]))
        .build()?;

    let _: NlRouterReceiverHandle<Rtm, Rtmsg> = rtnl.send(
        what,
        NlmF::CREATE | NlmF::REQUEST,
        NlPayload::Payload(rtmsg),
    )?;

    Ok(())
}

/// Add or delete IPv4 addresses for eth0 (interface index 2)
fn addr4_eth0(rtnl: &NlRouter, what: Rtm, addr: Ipv4Addr, prefix_len: u8) -> Result<()> {
    let ifaddrmsg = IfaddrmsgBuilder::default()
        .ifa_family(RtAddrFamily::Inet)
        .ifa_prefixlen(prefix_len)
        .ifa_scope(RtScope::Universe)
        .ifa_index(2)
        .rtattrs(RtBuffer::from_iter([
            RtattrBuilder::default()
                .rta_type(Ifa::Local)
                .rta_payload(addr.octets().to_vec())
                .build()?,
            RtattrBuilder::default()
                .rta_type(Ifa::Address)
                .rta_payload(addr.octets().to_vec())
                .build()?,
        ]))
        .build()?;

    let _: NlRouterReceiverHandle<Rtm, Ifaddrmsg> = rtnl.send(
        what,
        NlmF::CREATE | NlmF::REQUEST,
        NlPayload::Payload(ifaddrmsg),
    )?;

    Ok(())
}

/// Send DISCOVER with Rapid Commit, process ACK, configure address and route
fn do_dhcp(rtnl: &NlRouter) -> Result<()> {
    // Temporary link-local address and route avoid the need for raw sockets
    route4_eth0(rtnl, Rtm::Newroute, Ipv4Addr::UNSPECIFIED)?;
    addr4_eth0(rtnl, Rtm::Newaddr, Ipv4Addr::new(169, 254, 1, 1), 16)?;

    // Send request (DHCPDISCOVER)
    let socket = UdpSocket::bind("0.0.0.0:68").expect("Failed to bind");
    let mut buf = [0; 576 /* RFC 2131, Section 2 */ ];

    const REQUEST: &[u8; 300 /* From RFC 951: >= 60 B of options */ ] = const_str::concat_bytes!(
        1, // BOOTREQUEST
        0x01, // Hardware address type: Ethernet
        6, // Hardware address length
        0, // DHCP relay Hops
        [1, 2, 3, 4], // Transaction ID: we're the only client, use a fixed one
        [0, 0], // Seconds elapsed since beginning of acquisition or renewal
        [0x80, 0x0], // DHCP message flags: Broadcast
        [0; 16], // All-zero ciaddr, yiaddr, siaddr, giaddr
        [0; 16], // Client hardware address, not set as we're the only client
        [0; 64], // Server host name
        [0; 128], // Boot file name
        [0x63, 0x82, 0x53, 0x63], // Magic cookie prefix before options
        // Options
        [
            53, 1, 1, // DHCPDISCOVER
            80, 0, // Rapid Commit (RFC 4039)
        ],
        0xff, // End of options
        [0; 54], // Pad (up to 300 bytes)
    );

    socket.set_broadcast(true)?;
    socket.send_to(REQUEST, "255.255.255.255:67")?;

    // Keep IPv6-only fast
    let _ = socket.set_read_timeout(Some(Duration::from_millis(100)));

    // Get and process response (DHCPACK) if any
    if let Ok((len, _)) = socket.recv_from(&mut buf) {
        let msg = &mut buf[..len];

        let addr = Ipv4Addr::new(msg[16], msg[17], msg[18], msg[19]);
        let mut netmask = Ipv4Addr::UNSPECIFIED;
        let mut router = Ipv4Addr::UNSPECIFIED;
        let mut mtu: u16 = 65520;
        let mut p: usize = 240;
        let mut resolv = fs::File::options()
            .append(true)
            .open("/etc/resolv.conf")
            .context("Failed to open /etc/resolv.conf")?;

        while p < len {
            let o = msg[p];

            if o == 0xff {
                // Option 255: End (of options)
                break;
            }

            let l: u8 = msg[p + 1];
            p += 2; // Length doesn't include code and length field itself

            if o == 1 {
                // Option 1: Subnet Mask
                netmask = Ipv4Addr::new(msg[p], msg[p + 1], msg[p + 2], msg[p + 3]);
            } else if o == 3 {
                // Option 3: Router
                router = Ipv4Addr::new(msg[p], msg[p + 1], msg[p + 2], msg[p + 3]);
            } else if o == 6 {
                // Option 6: Domain Name Server
                for dns_p in (p..p + l as usize).step_by(4) {
                    let dns =
                        Ipv4Addr::new(msg[dns_p], msg[dns_p + 1], msg[dns_p + 2], msg[dns_p + 3]);
                    resolv
                        .write_all(format!("nameserver {dns}\n").as_bytes())
                        .context("Failed to write to resolv.conf")?;
                }
            } else if o == 26 {
                // Option 26: Interface MTU
                mtu = ((msg[p] as u16) << 8) | msg[p + 1] as u16;

                // We don't know yet if IPv6 is available: don't go below 1280 B
                mtu = mtu.clamp(1280, 65520);
            }

            p += l as usize;
        }

        let prefix_len: u8 = netmask.to_bits().leading_ones() as u8;

        // Drop temporary address and route, configure what we got instead
        route4_eth0(rtnl, Rtm::Delroute, Ipv4Addr::UNSPECIFIED)?;
        addr4_eth0(rtnl, Rtm::Deladdr, Ipv4Addr::new(169, 254, 1, 1), 16)?;

        addr4_eth0(rtnl, Rtm::Newaddr, addr, prefix_len)?;
        route4_eth0(rtnl, Rtm::Newroute, router)?;

        mtu_eth0(rtnl, mtu.into())?;
    } else {
        // Clean up: we're clearly too cool for IPv4
        route4_eth0(rtnl, Rtm::Delroute, Ipv4Addr::UNSPECIFIED)?;
        addr4_eth0(rtnl, Rtm::Deladdr, Ipv4Addr::new(169, 254, 1, 1), 16)?;
    }

    Ok(())
}

/// Wait for SLAAC to complete or fail
fn wait_for_slaac(rtnl: &NlRouter) -> Result<()> {
    let mut global_seen = false;
    let mut global_wait = true;
    let mut ll_seen = false;

    // Busy-netlink-loop until we see a link-local address, and a global unicast
    // address as long as we might expect one (see below)
    while !ll_seen || (global_wait && !global_seen) {
        let ifaddrmsg = IfaddrmsgBuilder::default()
            .ifa_family(RtAddrFamily::Inet6)
            .ifa_prefixlen(0)
            .ifa_scope(RtScope::Universe)
            .ifa_index(2)
            .build()?;

        let recv = rtnl.send(Rtm::Getaddr, NlmF::ROOT, NlPayload::Payload(ifaddrmsg))?;

        for response in recv {
            let header: Nlmsghdr<Rtm, Ifaddrmsg> = response?;
            if let NlPayload::Payload(p) = header.nl_payload() {
                if p.ifa_scope() == &RtScope::Link {
                    // A non-tentative link-local address implies we sent a
                    // router solicitation that didn't get any response
                    // (IPv4-only)? Stop waiting for the router in that case
                    if *p.ifa_flags() & IfaF::TENTATIVE != IfaF::TENTATIVE {
                        global_wait = false;
                    }

                    ll_seen = true;
                } else if p.ifa_scope() == &RtScope::Universe {
                    global_seen = true;
                }
            }
        }
    }

    Ok(())
}

pub fn configure_network() -> Result<()> {
    // Allow unprivileged users to use ping, as most distros do by default.
    {
        let mut file = fs::File::options()
            .write(true)
            .open("/proc/sys/net/ipv4/ping_group_range")
            .context("Failed to open ipv4/ping_group_range for writing")?;

        file.write_all(format!("{} {}", 0, 2147483647).as_bytes())
            .context("Failed to extend ping group range")?;
    }

    {
        let hostname =
            fs::read_to_string("/etc/hostname").unwrap_or("placeholder-hostname".to_string());
        let hostname = if let Some((hostname, _)) = hostname.split_once('\n') {
            hostname.to_owned()
        } else {
            hostname
        };
        sethostname(hostname.as_bytes()).context("Failed to set hostname")?;
    }

    let (rtnl, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty())?;
    rtnl.enable_strict_checking(true)?;

    // Disable neighbour solicitations (dodge DAD), bring up link to start SLAAC
    {
        // IFF_NOARP | IFF_UP in one shot delays router solicitations, avoid it
        flags_eth0(&rtnl, Iff::NOARP, Iff::NOARP)?;
        flags_eth0(&rtnl, Iff::UP, Iff::UP)?;
    }

    // Configure IPv4
    {
        do_dhcp(&rtnl)?;
    }

    // Ensure IPv6 setup is done, if available
    {
        wait_for_slaac(&rtnl)?;
    }

    // Re-enable neighbour solicitations and ARP requests
    {
        flags_eth0(&rtnl, Iff::NOARP, Iff::empty())?;
    }

    Ok(())
}
