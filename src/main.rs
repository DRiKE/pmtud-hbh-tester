#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate pnet;
extern crate structopt;
extern crate byteorder;


use byteorder::{ByteOrder, LittleEndian, NetworkEndian, WriteBytesExt};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::MutablePacket;
use pnet::packet::PacketSize;
use structopt::StructOpt;

use std::net::Ipv6Addr;

#[derive(Debug, StructOpt)]
struct Opt {
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
        [17, 0, self.opt_type, self.opt_length,
        (self.mtu1 >> 8) as u8, (self.mtu1 & 0xff) as u8,
        (self.mtu2 >> 8) as u8, (self.mtu2 & 0xff) as u8
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

    let mut packet = MutableEthernetPacket::owned(vec![0; MutableEthernetPacket::minimum_packet_size() + ipv6.packet_size()]).unwrap();
    packet.set_ethertype(EtherTypes::Ipv6);
    packet.set_payload(ipv6.packet_mut());
    packet
}

fn main() {
    let opt = Opt::from_args();
    println!("{:?}", opt);
    let interface_name = opt.interface;
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    let mut frame = base_packet("1::1".parse().unwrap(), "2::1".parse().unwrap(), 0x1234);
    frame.set_source(interface.mac_address());
    frame.set_destination(opt.dmac);

    println!("{:?}", interface);
    let (mut tx, mut _rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    println!("1");
    tx.send_to(frame.packet_mut(), None);
    println!("2");
}
