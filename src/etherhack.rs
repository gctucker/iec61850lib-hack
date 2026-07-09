// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Guillaume Tucker

// cargo build && sudo target/debug/iec_61850_hack

use pnet;
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;

pub fn sink() -> Vec<u8> {
    println!("Starting Ethernet sink...");
    let iface_name = "lo";
    // let iface_name = "wlp2s0";
    // let iface_name = "enp7s0";
    let interface_names_match =
        |iface: &NetworkInterface| iface.name == iface_name;
    let interfaces = datalink::interfaces();
    let interface =
        interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    println!("Interface: {0}", interface.name);

    let (mut _tx, mut rx) = match datalink::channel(
        &interface, Default::default()) {
        Ok(Ethernet(_tx, rx)) => (_tx, rx),
        Ok(_) => panic!(
            "Unhandled channel type"
        ),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}", e
        )
    };

    if let Some(mac) = interface.mac {
        let macaddr = mac.octets();
        print!("MAC address: ");
        println!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                 macaddr[0], macaddr[1], macaddr[2],
                 macaddr[3], macaddr[4], macaddr[5]
        );
    }

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                let ethtype = packet.get_ethertype().0;
                if ethtype == 0x88ba {
                    // ToDo: callback to handle the packet or iterator or pipe
                    return packet.packet().to_vec();
                }
            },
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

pub fn open(iface_name: &str) -> Channel {
    let interface_names_match =
        |iface: &NetworkInterface| iface.name == iface_name;
    let interfaces = datalink::interfaces();
    let interface =
        interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    let (mut tx, mut rx) = match datalink::channel(
        &interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!(
            "Unhandled channel type"
        ),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}", e
        )
    };

    Ethernet(tx, rx)
}

pub fn recv(chan: &mut Channel) -> Vec<u8> {
    let Ethernet(tx, rx) = chan else { panic!("Dang"); };

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                let ethtype = packet.get_ethertype().0;
                if ethtype == 0x88ba {
                    return packet.packet().to_vec();
                }
            },
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
