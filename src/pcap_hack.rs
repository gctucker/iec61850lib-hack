// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Guillaume Tucker

use std::fs::File;
use std::io::Write;

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
