// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Guillaume Tucker

use pnet;
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;

pub fn sink() {
    println!("Starting Ethernet sink...");
    // let iface_name = "lo";
    let iface_name = "wlp2s0";
    let interface_names_match =
        |iface: &NetworkInterface| iface.name == iface_name;
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();
    if let Some(mac) = interface.mac {
        println!("Interface: {0}", interface.name);
        let macaddr = mac.octets();
        print!("MAC address: ");
        println!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                 macaddr[0], macaddr[1], macaddr[2],
                 macaddr[3], macaddr[4], macaddr[5]
        );
    }

    // ToDo: figure out how to use any MAC and not just Ethernet?
    // ToDo: also check the bittwist / bpftrace hack works on the same iface
    let (mut tx, mut rx) = match datalink::channel(
        &interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
};

    //let (mut tx, mut rx) = datalink::channel(&interface, Default::default()).unwrap();
    let chan = datalink::channel(&interface, Default::default());

/*
    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();

                // Constructs a single packet, the same length as the one received,
                // using the provided closure. This allows the packet to be constructed
                // directly in the write buffer, without copying. If copying is not a
                // problem, you could also use send_to.
                //
                // The packet is sent once the closure has finished executing.
                tx.build_and_send(1, packet.packet().len(),
                    &mut |mut new_packet| {
                        let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();

                        // Create a clone of the original packet
                        new_packet.clone_from(&packet);

                        // Switch the source and destination
                        new_packet.set_source(packet.get_destination());
                        new_packet.set_destination(packet.get_source());
                });
            },
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
}
    */

    println!("Done.");
}
