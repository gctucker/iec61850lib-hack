use iec_61850_lib::encode_goose::encode_goose;
use iec_61850_lib::types::{
    EthernetHeader,
    IECGoosePdu,
    IECData,
    TimeQuality,
    Timestamp,
};

fn main() {
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

    match encode_goose(&header, &pdu) {
        Ok(frame) => {
            println!("Encoded GOOSE frame: {} bytes", frame.len());
            // Send frame to network...
        }
        Err(e) => eprintln!("Encoding failed: {:?}", e),
    }
}
