// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Guillaume Tucker

use std::fs::File;
use std::io::Write;

use iec_61850::decode_basics::decode_ethernet_header;
use iec_61850::decode_goose::decode_goose_pdu;
use iec_61850::decode_smv::{decode_smv, is_smv_frame};
use iec_61850::encode_goose::encode_goose;
use iec_61850::encode_smv::encode_smv;
use iec_61850::types::{
    EthernetHeader,
    IECGoosePdu,
    IECData,
    Sample,
    SavAsdu,
    SavPdu,
    TimeQuality,
    Timestamp,
};

mod etherhack;
mod pcap_hack;
mod svgen;

use svgen::{Generator, Phase};

fn do_encode_goose() -> Vec<u8> {
    let header = EthernetHeader {
        dst_addr: [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00],
        src_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        tpid: Some([0x81, 0x00]),
        tci: Some([0x80, 0x00]),
        ether_type: [0x88, 0xb8],
        appid: [0x00, 0x01],
        length: [0x00, 0x00],
    };

    let timestamp = Timestamp {
        seconds: 1698502245,
        fraction: 2097152,
        quality: TimeQuality {
            leap_second_known: false,
            clock_failure: false,
            clock_not_synchronized: false,
            time_accuracy: 10,
        },
    };

    let pdu = IECGoosePdu {
        go_cb_ref: "IED1$GO$GoCB01".to_string(),
        time_allowed_to_live: 2000,
        dat_set: "IED1$Dataset1".to_string(),
        go_id: "IED1_GOOSE1".to_string(),
        t: timestamp,
        st_num: 1,
        sq_num: 0,
        simulation: false,
        conf_rev: 1,
        nds_com: false,
        num_dat_set_entries: 2,
        all_data: vec![
            IECData::Boolean(true),
            IECData::Int(12345),
        ],
    };

    encode_goose(&header, &pdu).unwrap()
}

fn do_decode_goose(packet: &[u8]) {
    let mut header = EthernetHeader::default();
    let pos = decode_ethernet_header(&mut header, packet);

    match decode_goose_pdu(packet, pos) {
        Ok(pdu) => {
            println!("GOOSE ID: {}", pdu.go_id);
            println!("State Number: {}", pdu.st_num);
            println!("Sequence Number: {}", pdu.sq_num);
            println!("Data entries: {}", pdu.all_data.len());

            for data in &pdu.all_data {
                println!("  {:?}", data);
            }
        }
        Err(e) => eprintln!("Decoding failed: {:?}", e),
    }
}

fn do_encode_smv() -> Vec<u8> {
    let header = EthernetHeader {
        dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],
        src_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        tpid: None,
        tci: None,
        ether_type: [0x88, 0xba],  // SMV EtherType
        appid: [0x40, 0x00],
        length: [0x00, 0x00],
    };

    let samples = vec![
        Sample::new(1000, 0),    // value, quality
        Sample::new(2000, 0),
        Sample::new(3000, 0),
    ];

    let asdu = SavAsdu {
        msv_id: "AA1E1Q01BCLD1/LLN0.dataSetName".to_string(),
        dat_set: None,
        smp_cnt: 0,
        conf_rev: 1,
        refr_tm: None,
        smp_synch: 0,
        smp_rate: Some(4800),
        all_data: samples,
        smp_mod: None,
        gm_identity: None,
    };

    let pdu = SavPdu {
        sim: true,
        no_asdu: 1,
        sav_asdu: vec![asdu],
        security: None,
    };

    encode_smv(&header, &pdu).unwrap()
}


fn encode_sample(sample: &[f32], sfreq: f32) -> Vec<u8> {
    let mut samples: Vec<Sample> = Vec::with_capacity(sample.len());
    for chan in sample {
        samples.push(Sample::new((chan * 100.0).round() as i32, 0));
    }

    let header = EthernetHeader {
        dst_addr: [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01],  // TBD
        src_addr: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],  // from devkit config
        tpid: None,
        tci: None,
        ether_type: [0x88, 0xba],
        appid: [0x40, 0x00],
        length: [0x00, 0x00],
    };

    let asdu = SavAsdu {
        msv_id: "svIDdevkit000000".to_string(),
        dat_set: None,
        smp_cnt: 1,
        conf_rev: 1,
        refr_tm: None,
        smp_synch: 0,
        smp_rate: Some(sfreq as u16),
        all_data: samples,
        smp_mod: None,
        gm_identity: None,
    };

    let pdu = SavPdu {
        sim: true,
        no_asdu: 1,
        sav_asdu: vec![asdu],
        security: None,
    };

    encode_smv(&header, &pdu).unwrap()
}

fn decode_sample(packet: &[u8]) -> SavPdu {
    let mut header = EthernetHeader::default();
    let pos = decode_ethernet_header(&mut header, packet);

    match decode_smv(packet, pos) {
        Ok(pdu) => {
            pdu
        }
        Err(e) => panic!("Decoding failed: {:?}", e),
    }
}

fn do_decode_smv(packet: &[u8]) {
    let mut header = EthernetHeader::default();
    let pos = decode_ethernet_header(&mut header, packet);

    match decode_smv(packet, pos) {
        Ok(pdu) => {
            println!("Number of ASDUs: {}", pdu.no_asdu);

            for asdu in &pdu.sav_asdu {
                println!("SV ID: {}", asdu.msv_id);
                println!("Sample Count: {}", asdu.smp_cnt);
                println!("Number of samples: {}", asdu.all_data.len());

                // Process samples
                for (i, sample) in asdu.all_data.iter().enumerate() {
                    println!(
                        "  Sample {}: value={}, quality={}",
                        i, sample.value,
                        if sample.quality.is_good() { "good" } else { "bad" }
                    );
                }
            }
        }
        Err(e) => eprintln!("Decoding failed: {:?}", e),
    }
}

fn main() {
    println!("--- GOOSE ---");
    let frame = do_encode_goose();
    println!("Encoded GOOSE frame: {} bytes", frame.len());
    do_decode_goose(&frame);

    println!("\n--- SMV ---");
    let frame = do_encode_smv();
    println!("Encoded SMV frame: {} bytes", frame.len());
    println!("Saving to sv.bin");
    let mut dump = File::create("sv.bin").unwrap();
    dump.write_all(&frame).unwrap();
    do_decode_smv(&frame);

    println!("\nGenerating data and saving to dump.pcap");
    /* ToDo: use group of 8 generators for 8 channels */
    let mut gen = Generator::new50hz(Phase::Ph0);
    let sfreq = gen.sfreq();
    let mut dump = pcap_hack::open("dump.pcap");
    let mut fnum = 0;
    for iter in 0..3 {
        let data = gen.run(0.008);
        for (time, value) in data {
            let frame = encode_sample(&[value], sfreq);
            println!("[{iter:02}:{fnum:04}]  {time:8.6}  {value:06}");
            pcap_hack::append(&mut dump, &frame);
            fnum += 1;
        }
    }
    dump.flush().unwrap();

    println!("\nReading {fnum} frames from Ethernet...");
    let mut eth = etherhack::open("enp7s0");
    for i in 0..fnum {
        let pkt = etherhack::recv(&mut eth);
        if !is_smv_frame(&pkt) {
            panic!("INVALID SV FRAME");
        }
        print!("[{0:04} {1}]", i, pkt.len());
        let pdu = decode_sample(&pkt);
        for asdu in &pdu.sav_asdu {
            for sample in &asdu.all_data {
                let value = sample.value as f32 / 100.0;
                println!("  {0:06}  {1:8.3}", sample.value, value);
            }
        }
    }
}
