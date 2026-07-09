// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Guillaume Tucker

use std::fs::File;
use std::io::Write;

use libc;
use pcap::{Capture, Linktype, Packet, PacketHeader, Savefile};

pub fn pcap() {
    let header = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    let mut buffer = Vec::new();
    buffer.push(0xaa);
    println!("Writing output.pcap");
    let mut output = File::create("output.pcap").unwrap();
    output.write_all(&header).unwrap();
    output.write_all(&buffer).unwrap();
}

pub fn open(path: &str) -> Savefile {
    let cap = Capture::dead(Linktype::ETHERNET).unwrap();
    cap.savefile(path).unwrap()
}

pub fn append(dump: &mut Savefile, data: &[u8]) {
    let len = data.len() as u32;
    let hdr = PacketHeader {
        ts: libc::timeval {tv_sec: 0, tv_usec: 0},
        caplen: len,
        len: len,
    };
    let pkt = Packet {header: &hdr, data: data};
    dump.write(&pkt);
}
