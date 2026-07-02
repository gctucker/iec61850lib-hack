// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Guillaume Tucker


// ToDo: read packets sent from the pcap using iec6150 crate + network socket
// ToDo: sudo apt install libpcap-dev

use std;
use libc;
use pcap::{Capture, Linktype, Packet, PacketHeader};

struct Generator {
    _f: f32,
    a: f32,
    ph: f32,
    t: f32,
    w: f32,
    step: f32,
}

enum Phase {
    Ph0 = 0,
    Ph1 = 1,
    Ph2 = 2,
}

fn make50hz(phase: Phase) -> Generator {
    let freq = 50.0;
    let peak = 240.0 * 2_f32.sqrt();
    let ph = phase as u32 as f32 * 2.0 * std::f32::consts::PI / 3.0;
    let w = 2.0 * std::f32::consts::PI * freq;
    Generator{_f: 50.0, a: peak, ph: ph, t: 0.0, w: w, step: 0.00025}
}

impl Generator {
    fn gen(&self) -> f32 {
        let x: f32 = self.w * self.t + self.ph;
        self.a * x.sin()
    }

    fn step(&mut self) {
        self.t += self.step;
    }
}

pub fn hello() {
    let mut gen = make50hz(Phase::Ph0);
    let mut cap = Capture::dead(Linktype::ETHERNET).unwrap();
    let hdr = PacketHeader {
        ts: libc::timeval { tv_sec: 1, tv_usec: 0 },
        caplen: 2,
        len: 2,
    };
    let data = vec![0x34, 0x12];
    let pkt = Packet {header: &hdr, data: &data};
    let mut dump = cap.savefile("dump.pcap").unwrap();
    dump.write(&pkt);
    while gen.t < 0.01 /*3.0*/ {
        let value = gen.gen();
        println!("value({}): {}", gen.t, value);
        gen.step();
    }
}
