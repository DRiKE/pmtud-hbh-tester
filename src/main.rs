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
use pnetlink::packet::route::link::{Link, Links};
use pnetlink::packet::route::neighbour::{NeighbourFlags, NeighbourState, Neighbours};

use byteorder::{ByteOrder, LittleEndian, NetworkEndian, WriteBytesExt};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::MutablePacket;
use pnet::packet::PacketSize;
use structopt::StructOpt;

use std::net::Ipv6Addr;

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
    /// Destination MAC
    #[structopt(long = "dmac", parse(try_from_str))]
    dmac: MacAddr,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct HBH {
    opt_type: u8,
    opt_length: u8,
    mtu1: u16,
    mtu2: u16,
}

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
    // create UDP dataframe
    let mut ipv6 = MutableIpv6Packet::owned(vec![0u8; 1000]).unwrap();
    ipv6.set_version(6);
    ipv6.set_source(saddr);
    ipv6.set_destination(daddr);
    ipv6.set_next_header(IpNextHeaderProtocols::Hopopt);

    let hbh = HBH {
        opt_type: 0b00111110,
        opt_length: 0b100,
        mtu1: mtu1,
        mtu2: 0,
    };
    //println!("len: {}", serialize(&hbh).unwrap().len());
    ipv6.set_payload_length(8);
    ipv6.set_payload(&hbh.serialize());

    let mut packet = MutableEthernetPacket::owned(vec![
        0;
        MutableEthernetPacket::minimum_packet_size()
            + ipv6.packet_size()
    ]).unwrap();
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

fn get_neighbour_info(link: &Link) -> MacAddr {
    let mut conn = NetlinkConnection::new();
    let neighbours = conn
        .iter_neighbours(Some(link))
        .unwrap()
        .collect::<Vec<_>>();

    let next_hop = neighbours
        .iter()
        .filter(|&neighbour| {
            neighbour.get_state() == NeighbourState::REACHABLE
                && neighbour.get_flags().contains(NeighbourFlags::ROUTER)
        }).next()
        .unwrap();
    next_hop.get_ll_addr().unwrap()
}

fn fill_routing_info(oif: &str) -> () {
    let link = get_link_info(oif.to_string());
    let next_hop = get_neighbour_info(&link);
    let mtu1 = link.get_mtu().unwrap();
    let smac = link.get_hw_addr().unwrap();
    info!(
        "using mtu {:?} and smac {:?}, next hop {:?}",
        mtu1, smac, next_hop
    );
    // FIXME getting next_hop etc based on the v6 dst address
    // is not yet possible because pnetlink does not support it (March 30 2019)
    //
    //for route in Route::iter_routes(&mut conn) {
    //    println!("{:?}", route);
    //}

    // For now, fill info based on passed outgoing interface
}

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
    let interface_name = opt.interface;
    fill_routing_info(&interface_name);
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    //TODO get source address from link interface, and dst from opt
    //TODO implement overriding of defaults, e.g. dmac is derived from --interface but can be
    //passed as --dmac (which then has preference)
    //same for mtu
    let mut frame = base_packet("1::1".parse().unwrap(), "2::1".parse().unwrap(), 0x1234);
    frame.set_source(interface.mac_address());
    frame.set_destination(opt.dmac);

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
