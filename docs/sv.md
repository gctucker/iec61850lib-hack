Sampled Value Format
====================

First section with low-level data:

| Offset | Length | Name       | Description             |
|--------|--------|------------|-------------------------|
| 0x00   | 0x06   | MAC SRC    | Source MAC address      |
| 0x06   | 0x06   | MAC DST    | Destination MAC address |
| 0x0C   | 0x02   | Ethertype  | Ethernet Type: 0x88BA   |
| 0x0E   | 0x02   | AppId      | Application id: 0x4000  |
| 0x10   | 0x02   | Length     | Total packet length     |
| 0x12   | 0x02   | Reserved 1 | Reserved bytes 1        |
| 0x14   | 0x02   | Reserved 2 | Reserved bytes 2        |

Second section with actual payload, with variable lengths set to 1 and SV id
string length set to 16 and sample data length set to 64 for simplicity:

| Offset | Length | Name       | Description                               |
|--------|--------|------------|-------------------------------------------|
| 0x16   | 0x02   | savPDU len | 0x60, savPDU total length                 |
| 0x18   | 0x03   | Num ASDU   | 0x80, field length = 1, number of ASDUs   |
| 0x1B   | 0x02   | Seq ASDU   | 0xA2, length                              |
| 0x1D   | 0x02   | Seq ASDU1  | 0x30, length                              |
| 0x1F   | 0x02   | SvID len   | 0x80, SV id string length = 16            |
| 0x21   | 0x10   | SvID       | "svIDdevkit000000"                        |
| 0x31   | 0x04   | smpCount   | 0x82, field length = 2, number of samples |
| 0x35   | 0x06   | confRev    | 0x83, field length = 4, 4 bytes (?)       |
| 0x3B   | 0x03   | smpSync    | 0x85, field length = 1, sync byte (?)     |
| 0x3E   | 0x02   | Data len   | 0x87, length = 64 (0x40)                  |
| 0x40   | 0x40   | Data       | Sample value data                         |
