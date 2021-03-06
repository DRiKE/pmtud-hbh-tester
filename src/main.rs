#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate byteorder;
extern crate pnet;
extern crate pnetlink;
extern crate structopt;
#[macro_use]
extern crate log;
extern crate simplelog;

use pnetlink::packet::netlink::NetlinkConnection;
//use pnetlink::packet::route::route::{Route, RoutesIterator};
use pnetlink::packet::route::addr::{Addr, Scope};
use pnetlink::packet::route::link::{Link, Links};
use pnetlink::packet::route::neighbour::{NeighbourFlags, NeighbourState, Neighbours};

//use byteorder::{ByteOrder, LittleEndian, NetworkEndian, WriteBytesExt};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::udp::{ipv6_checksum, MutableUdpPacket, Udp};
use pnet::packet::{MutablePacket, Packet, PacketSize};
use structopt::StructOpt;

use std::net::{IpAddr, Ipv6Addr};

use simplelog::{Config, LevelFilter, TermLogger};

const HBH_SIZE: usize = 8;
const HBH_TYPE: u8 = 0b0011_1110;

#[derive(Debug, StructOpt)]
struct Opt {
    /// Verbose/logging
    #[structopt(short = "v", parse(from_occurrences))]
    verbose: u64,

    /// listening mode
    #[structopt(short = "l", long = "listen", name = "listen", requires = "interface")]
    listen: bool,

    /// outgoing/listening interface
    #[structopt(short = "i", long = "interface")]
    interface: String,

    /// Next-hop MAC
    #[structopt(long = "dmac", parse(try_from_str))]
    dmac: Option<MacAddr>,

    /// IPv6 source address
    #[structopt(long = "saddr", parse(try_from_str))]
    saddr: Option<Ipv6Addr>,

    /// IPv6 destination address
    #[structopt(long = "daddr", parse(try_from_str), required_unless = "listen")]
    daddr: Option<Ipv6Addr>,

    /// MTU to send out
    #[structopt(long = "mtu1")]
    mtu1: Option<u32>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct HBH {
    next_header: u8,
    eh_length: u8,
    opt_type: u8,
    opt_length: u8,
    mtu1: u16,
    mtu2: u16,
}

// TODO make the hardcoded [17, 0] nicer, maybe generalize to 'EH' or something
// TODO impl more functions, set_mtu1, set_mtu2, toggle_R_flag
// TODO impl set_next_header
impl HBH {
    fn new() -> HBH {
        HBH {
            next_header: 17,
            eh_length: 0,
            opt_type: HBH_TYPE,
            opt_length: 0b100,
            mtu1: 0,
            mtu2: 0, // contains R flag TODO MSB or LSB?
        }
    }

    //MSB is the R flag
    fn _set_r_flag(&mut self) {
        self.mtu2 |= 1 << 15;
    }
    fn _unset_r_flag(&mut self) {
        self.mtu2 &= 0x7fff;
    }
    // ---

    //LSB is the R flag
    fn set_r_flag(&mut self) {
        self.mtu2 |= 0b0000_0001;
    }
    fn unset_r_flag(&mut self) {
        self.mtu2 &= 0b1111_1110;
    }
    fn get_r_flag(&self) -> u16 {
        self.mtu2 & 0x0001
    }

    fn get_mtu2(&self) -> u16 {
        self.mtu2 & 0xfffe
    }
    fn set_mtu2(&mut self, new_mtu2: u16) {
        self.mtu2 = (new_mtu2 / 2) << 1 | self.get_r_flag();
    }

    fn serialize(&self) -> [u8; 8] {
        [
            self.next_header,
            self.eh_length,
            self.opt_type,
            self.opt_length,
            (self.mtu1 >> 8) as u8,
            (self.mtu1 & 0xff) as u8,
            (self.mtu2 >> 8) as u8,
            (self.mtu2 & 0xff) as u8,
        ]
    }

    fn from(buf: &[u8]) -> HBH {
        HBH {
            next_header: buf[0],
            eh_length: buf[1],
            opt_type: buf[2],
            opt_length: buf[3],
            mtu1: (buf[4] as u16) << 8 | buf[5] as u16,
            mtu2: (buf[6] as u16) << 8 | buf[7] as u16,
        }
    }
}
impl std::fmt::Display for HBH {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_fmt(format_args!(
            "mtu1: {}, mtu2: {}, flag: {}",
            self.mtu1,
            self.get_mtu2(),
            self.get_r_flag()
        ))
    }
}

// TODO implement TCP or ICMP as well?
fn base_packet<'a>(
    saddr: Ipv6Addr,
    daddr: Ipv6Addr,
    mtu1: u16,
    r_flag: bool,
    mtu2: u16,
) -> MutableEthernetPacket<'a> {
    let udp_payload = vec![0xBE, 0xEF];
    let mut udp: MutableUdpPacket = MutableUdpPacket::owned(vec![
        0u8;
        MutableUdpPacket::minimum_packet_size()
            + udp_payload.len()
    ])
    .unwrap();
    udp.populate(
        &(Udp {
            source: 12345,
            destination: 53,
            length: (MutableUdpPacket::minimum_packet_size() + udp_payload.len()) as u16, // header, + payload of 2
            checksum: 0,
            payload: udp_payload,
        }),
    );
    let checksum = ipv6_checksum(&udp.to_immutable(), &saddr, &daddr);
    udp.set_checksum(checksum);

    let mut hbh = HBH::new();
    hbh.mtu1 = mtu1;
    if r_flag {
        hbh.set_r_flag();
    }
    hbh.set_mtu2(mtu2);

    // apparently the libpnet udp.packet_size() does not correctly return the size of the entire
    // header+payload, use .packet_mut().len() as a workaround.
    let ipv6_size = MutableIpv6Packet::minimum_packet_size() + HBH_SIZE + &udp.packet_mut().len();
    let mut ipv6 = MutableIpv6Packet::owned(vec![0u8; ipv6_size]).unwrap();
    ipv6.set_version(6);
    ipv6.set_source(saddr);
    ipv6.set_destination(daddr);
    ipv6.set_hop_limit(64);
    ipv6.set_next_header(IpNextHeaderProtocols::Hopopt);

    ipv6.set_payload_length((HBH_SIZE + &udp.packet_mut().len()) as u16); // HBH is 8 bytes
    ipv6.set_payload(&[&hbh.serialize()[..], &udp.packet_mut()].concat());

    let mut packet = MutableEthernetPacket::owned(vec![
        0;
        MutableEthernetPacket::minimum_packet_size()
            + ipv6.packet_size()
    ])
    .unwrap();
    packet.set_ethertype(EtherTypes::Ipv6);
    packet.set_payload(ipv6.packet_mut());
    packet
}

fn get_link_info(oif: String) -> Link {
    let mut conn = NetlinkConnection::new();
    let link = conn
        .iter_links()
        .unwrap()
        .filter(|link: &Link| link.get_name().unwrap() == oif)
        .next()
        .unwrap();
    link
}

fn get_address_info(link: &Link) -> Option<Ipv6Addr> {
    let mut conn = NetlinkConnection::new();
    if let Some(IpAddr::V6(addr)) = Addr::iter_addrs(&mut conn)
        .find(|addr| {
            addr.get_link_index() == link.get_index()
                && std::mem::discriminant(&addr.get_scope())
                    == std::mem::discriminant(&Scope::Universe)
                && addr.get_family() == 10 // FIXME no constant for this in pnetlink?
        })
        .and_then(|addr| addr.get_ip())
    {
        Some(addr)
    } else {
        None
    }
}

fn get_neighbour_info(link: &Link) -> Option<MacAddr> {
    let mut conn = NetlinkConnection::new();
    let neighbours = conn
        .iter_neighbours(Some(link))
        .unwrap()
        .collect::<Vec<_>>();

    if let Some(next_hop) = neighbours.iter().find(|&neighbour| {
        (neighbour.get_state() == NeighbourState::REACHABLE
            || neighbour.get_state() == NeighbourState::STALE)
            && neighbour.get_flags().contains(NeighbourFlags::ROUTER)
    }) {
        // FIXME can we make this nicer using
        // https://doc.rust-lang.org/std/result/enum.Result.html#method.map_or_else
        // ??
        next_hop.get_ll_addr()
    } else {
        None
    }
}

struct RoutingInfo {
    saddr: Option<Ipv6Addr>,
    smac: MacAddr,
    next_hop: MacAddr,
    mtu1: u32,
}
fn get_routing_info(oif: &str) -> RoutingInfo {
    let link = get_link_info(oif.to_string());
    let next_hop = get_neighbour_info(&link).expect("no next-hop found");
    let mtu1 = link.get_mtu().unwrap();
    let smac = link.get_hw_addr().unwrap();
    let saddr = get_address_info(&link);
    info!(
        "netlink: mtu {:?} and smac {:?}, next hop {:?}, saddr {:?}",
        mtu1, smac, next_hop, saddr,
    );
    RoutingInfo {
        saddr,
        smac,
        next_hop,
        mtu1,
    }
    // FIXME getting next_hop etc based on the v6 dst address
    // is not yet possible because pnetlink does not support it (March 30 2019)
    //
    //for route in Route::iter_routes(&mut conn) {
    //    info!("{:?}", route);
    //}

    // For now, fill info based on passed outgoing interface
}

fn override_routing_info(routing_info: &mut RoutingInfo, opt: &Opt) {
    if let Some(dmac) = opt.dmac {
        warn!(
            "using passed dmac {} instead of {}",
            dmac, routing_info.next_hop
        );
        routing_info.next_hop = dmac;
    }
    if let Some(mtu1) = opt.mtu1 {
        warn!(
            "using passed mtu1 {} instead of {}",
            mtu1, routing_info.mtu1
        );
        routing_info.mtu1 = mtu1;
    }
    if let Some(passed_saddr) = opt.saddr {
        debug!("we have passed_saddr {}", passed_saddr);
        if let Some(netlink_saddr) = routing_info.saddr {
            warn!(
                "using passed saddr {} instead of {}",
                passed_saddr, netlink_saddr
            );
        } else {
            warn!(
                "using passed saddr {}, could not detect a valid saddr anyway",
                passed_saddr
            );
        }
        routing_info.saddr = Some(passed_saddr);
    }
}

//TODO refactor to not take Opt, but all the individual saddr/daddr so we can use it to send the
//response from listen()
fn send_probe(opt: &Opt, daddr: Ipv6Addr, r_flag: bool, mtu2: u16) {
    let interface_name = &opt.interface;
    let mut routing_info = get_routing_info(&interface_name);
    override_routing_info(&mut routing_info, &opt);

    //sanity check
    if routing_info.saddr.is_none() {
        error!("no saddr!");
        panic!("no saddr panic");
    } else {
        info!("using {}", routing_info.saddr.unwrap());
    }

    // Find the network interface with the provided name
    let interface_names_match = |iface: &NetworkInterface| iface.name == *interface_name;
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(interface_names_match)
        .expect("no interface with that name");

    //TODO unwrap should be replaced with decent error message 'no saddr found'
    let mut frame = base_packet(
        routing_info.saddr.unwrap(),
        daddr,
        routing_info.mtu1 as u16,
        r_flag,
        mtu2,
    );
    frame.set_source(routing_info.smac);
    frame.set_destination(routing_info.next_hop);

    let (mut tx, mut _rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    tx.send_to(frame.packet_mut(), None);
}

//TODO check for our specific HBH type
//TODO DRY the interface stuff from here and send_probe
//TODO loop indefinitly and catch SIGINT or something
fn listen(opt: &Opt) {
    // Find the network interface with the provided name
    let interface_name = &opt.interface;
    let interface_names_match = |iface: &NetworkInterface| iface.name == *interface_name;
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(interface_names_match)
        .expect("no interface with that name");
    let (mut _tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                if packet.get_source() != interface.mac_address() {
                    if let Some(probe) = is_hbh_probe(&packet) {
                        info!("got a probe! {}", probe);
                        if probe.get_r_flag() == 1 {
                            let r_flag = probe.get_mtu2() == 0;
                            info!(
                                "flag is set, sending a response with mtu2 of {}, r_flag {} ",
                                probe.mtu1, r_flag
                            );
                            send_probe(
                                &opt,
                                Ipv6Packet::new(packet.payload()).unwrap().get_source(),
                                r_flag,
                                probe.mtu1, // the received mtu1 will be reflected as mtu2 via this parameter
                            );
                        }
                    }
                }
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

// TODO filter on our specific type
fn is_hbh_probe(eth: &EthernetPacket) -> Option<HBH> {
    if eth.get_ethertype() == EtherTypes::Ipv6 {
        let ipv6: Ipv6Packet = Ipv6Packet::new(eth.payload()).unwrap();
        if ipv6.get_next_header() == IpNextHeaderProtocols::Hopopt {
            let hopopt = &ipv6.payload()[0..=HBH_SIZE - 1];
            if hopopt[2] == HBH_TYPE {
                return Some(HBH::from(hopopt));
            }
        }
    }
    None
}

fn main() {
    let opt = Opt::from_args();

    match opt.verbose {
        0 => TermLogger::init(LevelFilter::Warn, Config::default()).unwrap(),
        1 => TermLogger::init(LevelFilter::Info, Config::default()).unwrap(),
        2 | _ => TermLogger::init(LevelFilter::Debug, Config::default()).unwrap(),
    };

    //TODO add warning if an mtu1 > 65535 is passed
    info!("Passed options: {:?}", opt);

    if opt.listen {
        listen(&opt);
    } else {
        send_probe(
            &opt,
            opt.daddr
                .expect("not in listening mode, should have a --daddr passed"),
            true, // we want the R-flag set
            0,    //mtu2
        );
    }
}
