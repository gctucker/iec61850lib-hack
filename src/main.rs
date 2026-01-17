use iec_61850_lib::decode_basics::decode_ethernet_header;
use iec_61850_lib::decode_goose::decode_goose_pdu;
use iec_61850_lib::encode_goose::encode_goose;
use iec_61850_lib::types::{
    EthernetHeader,
    IECGoosePdu,
    IECData,
    TimeQuality,
    Timestamp,
};

fn do_encode_goose() -> Vec<u8> {
    let header = EthernetHeader {
        dst_addr: [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00],
        src_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        tpid: Some([0x81, 0x00]),
        tci: Some([0xa0, 0x00]),
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

fn main() {
    let frame = do_encode_goose();
    println!("Encoded GOOSE frame: {} bytes", frame.len());
    do_decode_goose(&frame);
}
