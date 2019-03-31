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
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::MutablePacket;
use pnet::packet::PacketSize;
use structopt::StructOpt;

use std::net::{IpAddr, Ipv6Addr};

use simplelog::{Config, LevelFilter, TermLogger};

#[derive(Debug, StructOpt)]
struct Opt {
    /// Verbose/logging
    #[structopt(short = "v", parse(from_occurrences))]
    verbose: u64,
    /// listening mode
    #[structopt(short = "l", long = "listen")]
    listen: Option<bool>,
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
    #[structopt(long = "daddr", parse(try_from_str))]
    daddr: Ipv6Addr,
    /// MTU to send out
    #[structopt(long = "mtu1")]
    mtu1: Option<u32>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct HBH {
    opt_type: u8,
    opt_length: u8,
    mtu1: u16,
    mtu2: u16,
}

// TODO make the hardcoded [17, 0] nicer, maybe generalize to 'EH' or something
// TODO impl more functions, set_mtu1, set_mtu2, toggle_R_flag
// TODO impl set_next_header
impl HBH {
    /*
    fn serialize<'p>(&'p self) -> &'p [u8] {
        //let mut buffer = [0u8; 6];
        let mut buffer = vec![];

        WriteBytesExt::write_u8(&mut buffer, self.opt_type);
        LittleEndian::write_u16(&mut buffer, self.mtu1);
        LittleEndian::write_u16(&mut buffer, self.mtu2);

        buffer.write_u16::<NetworkEndian>(1234).unwrap();
        &buffer.as_slice()
    }
    */
    fn new() -> HBH {
        HBH {
            opt_type: 0b0011_1110,
            opt_length: 0b100,
            mtu1: 0,
            mtu2: 0,
        }
    }
    fn set_r_flag(&mut self) {
        self.mtu2 |= 1 << 15;
    }
    fn unset_r_flag(&mut self) {
        self.mtu2 &= 0x7fff;
    }

    //TODO (?) fn set_mtu2, to safeguard the R flag

    fn serialize(&self) -> [u8; 8] {
        [
            17,
            0,
            self.opt_type,
            self.opt_length,
            (self.mtu1 >> 8) as u8,
            (self.mtu1 & 0xff) as u8,
            (self.mtu2 >> 8) as u8,
            (self.mtu2 & 0xff) as u8,
        ]
    }
}

fn base_packet(saddr: Ipv6Addr, daddr: Ipv6Addr, mtu1: u16) -> MutableEthernetPacket<'static> {
    //TODO create valid UDP dataframe so tshark etc don't throw warnings

    let mut ipv6 = MutableIpv6Packet::owned(vec![0u8; 1000]).unwrap();
    ipv6.set_version(6);
    ipv6.set_source(saddr);
    ipv6.set_destination(daddr);
    ipv6.set_next_header(IpNextHeaderProtocols::Hopopt);

    let mut hbh = HBH::new();
    hbh.mtu1 = mtu1;
    hbh.set_r_flag();

    //println!("len: {}", serialize(&hbh).unwrap().len());
    ipv6.set_payload_length(8);
    ipv6.set_payload(&hbh.serialize());

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
    //.or_else(None); //collect::<Vec<_>>();
}

fn get_neighbour_info(link: &Link) -> MacAddr {
    let mut conn = NetlinkConnection::new();
    let neighbours = conn
        .iter_neighbours(Some(link))
        .unwrap()
        .collect::<Vec<_>>();

    let next_hop = neighbours
        .iter()
        .find(|&neighbour| {
            neighbour.get_state() == NeighbourState::REACHABLE
                && neighbour.get_flags().contains(NeighbourFlags::ROUTER)
        })
        .unwrap();
    next_hop.get_ll_addr().unwrap()
}

struct RoutingInfo {
    saddr: Option<Ipv6Addr>,
    smac: MacAddr,
    next_hop: MacAddr,
    mtu1: u32,
}
fn get_routing_info(oif: &str) -> RoutingInfo {
    let link = get_link_info(oif.to_string());
    let next_hop = get_neighbour_info(&link);
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
    //    println!("{:?}", route);
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
        if let Some(netlink_saddr) = Some(routing_info.saddr) {
            warn!(
                "using passed saddr {} instead of {}",
                passed_saddr,
                netlink_saddr.unwrap()
            );
            routing_info.saddr = Some(passed_saddr);
        }
    }
}

//TODO split up main better
fn main() {
    let opt = Opt::from_args();

    match opt.verbose {
        0 => TermLogger::init(LevelFilter::Warn, Config::default()).unwrap(),
        1 => TermLogger::init(LevelFilter::Info, Config::default()).unwrap(),
        2 | _ => TermLogger::init(LevelFilter::Debug, Config::default()).unwrap(),
    };

    info!("Passed options: {:?}", opt);

    //TODO better error handling on non-existing interface names
    //think where we should check this (probably with NetLink)
    //perhaps fill_routing_info could return a Option<my_info_struct>
    let interface_name = &opt.interface;
    let mut routing_info = get_routing_info(&interface_name);
    override_routing_info(&mut routing_info, &opt);

    // Find the network interface with the provided name
    let interface_names_match = |iface: &NetworkInterface| iface.name == *interface_name;
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    //TODO v6 source address from interface?
    //also allow it to be passed, just for convenience

    //TODO unwrap should be replaced with decent error message 'no saddr found'
    let mut frame = base_packet(
        routing_info.saddr.unwrap(),
        opt.daddr,
        routing_info.mtu1 as u16,
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
