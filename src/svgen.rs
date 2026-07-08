// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Guillaume Tucker


// ToDo: read packets sent from the pcap using iec6150 crate + network socket
// ToDo: sudo apt install libpcap-dev

use std;
use libc;
use pcap::{Capture, Linktype, Packet, PacketHeader};

pub struct Generator {
    _f: f32,
    _a: f32,
    _ph: f32,
    _w: f32,
    _step: f32,
    t: f32,
    data: Vec<f32>,
}

enum Phase {
    Ph0 = 0,
    Ph1 = 1,
    Ph2 = 2,
}

impl Generator {
    pub fn new50hz(phase: Phase) -> Generator {
        let freq = 50.0;
        let peak = 240.0 * 2f32.sqrt();
        let ph = phase as u32 as f32 * 2.0 * std::f32::consts::PI / 3.0;
        let w = 2.0 * std::f32::consts::PI * freq;
        let step = 1.0 / 4000.0;
        Generator{
            _f: 50.0, _a: peak, _ph: ph, _w: w, _step: step,
            t: 0.0, data: Vec::new(),
        }
    }

    pub fn grow(&mut self, duration: f32) {
        self.data.reserve((duration / self._step) as usize);
    }

    pub fn sample(&mut self) -> f32 {
        let x: f32 = self._w * self.t + self._ph;
        let value = self._a * x.sin();
        self.data.push(value);
        self.t = self.data.len() as f32 * self._step;
        value
    }

    pub fn run(&mut self, duration: f32) {
        self.grow(duration);
        let finish = self.t + duration;
        while self.t < finish {
            self.sample();
        }
    }

    pub fn vec(&self) -> Vec<f32> {
        self.data.clone()
    }

    pub fn vec_i32(&self, scaling: f32) -> Vec<i32> {
        let mut vec: Vec<i32> = Vec::with_capacity(self.data.len());
        for sample in &self.data {
            vec.push((sample * scaling) as i32);
        }
        vec
    }
}

fn dump(path: &str) {
    let sv_id = b"svIDdevkit000000";
    let sv_id_len = sv_id.len() as u8;
    let mac_src_v = vec![0xc4, 0xb5, 0x12, 0x00, 0x00, 0x01];
    let mac_dst_v = vec![0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01];
    println!("SV ID LEN {sv_id_len} 0x{sv_id_len:02x}");

    let mut data: Vec<u8> = Vec::with_capacity(0x100);
    data.extend(mac_dst_v);
    data.extend(mac_src_v);
    data.extend(vec![
        0x88, 0xBA,              // Ethertype
        0x40, 0x00,              // AppId
        0x00, 0x62 + sv_id_len,  // Length (ToDo: calculate)
        0x00, 0x00, 0x00, 0x00,  // Reserved 1 & 2
    ]);
    data.extend(vec![
        0x60, 0x58 + sv_id_len,  // savPDU 0x60 length
        0x80, 0x01, 0x01,        // Number of asdu 0x80 L(1) 8
        0xa2, 0x53 + sv_id_len,  // Sequence of asdu 0xA2 L
        0x30, 0x51 + sv_id_len,  // Sequence ASDU1 0x30 L
        0x80, sv_id_len,         // SvID 0x80 L Values
    ]);
    data.extend(sv_id.to_vec()); // SvID string
    data.extend(vec![
        0x82, 0x02, 0x00, 0x00,              // smpCnt 0x82 L(2) value
        0x83, 0x04, 0x00, 0x00, 0x00, 0x01,  // ConfRev 0x83 L(4) value
        0x85, 0x01, 0x00,                    // smpSync 0x85 L(1) value
        0x87, 0x40,                          // Data 0x87 L(64) Dataset 8 CH
    ]);
    // ToDo: add payload with 64 bytes (8 channels with 8 bytes each?)
    let len = data.len() as u32;
    println!("Data length: {len} 0x{len:04x}");
    let hdr = PacketHeader {
        ts: libc::timeval {tv_sec: 0, tv_usec: 0},
        caplen: len,
        len: len,
    };
    let pkt = Packet {header: &hdr, data: data.as_slice()};
    let cap = Capture::dead(Linktype::ETHERNET).unwrap();
    let mut dump = cap.savefile(path).unwrap();
    println!("Saving to {path}");
    dump.write(&pkt);
}

pub fn hello() {
    let mut gen = Generator::new50hz(Phase::Ph0);
    dump("dump.pcap");
    while gen.t < 0.0 /*3.0*/ {
        let t = gen.t;
        let value = gen.sample();
        println!("value({}): {}", t, value);
    }
}

pub fn run(duration: f32) -> Generator {
    let mut gen = Generator::new50hz(Phase::Ph0);
    gen.run(duration);
    gen
}
