IEC61850 Rust Hacks
===================

This small project is to experiment with the
[`iec61850lib`](https://github.com/OpenEnergyTools/iec61850lib) Rust crate.

```
$ cargo run
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.17s
     Running `target/debug/iec_61850_hack`
--- GOOSE ---
Encoded GOOSE frame: 113 bytes
GOOSE ID: IED1_GOOSE1
State Number: 1
Sequence Number: 0
Data entries: 2
  Boolean(true)
  Int(12345)

--- SMV ---
Encoded SMV frame: 105 bytes
Number of ASDUs: 1
SV ID: AA1E1Q01BCLD1/LLN0.dataSetName
Sample Count: 0
Number of samples: 3
  Sample 0: value=1000, quality=true
  Sample 1: value=2000, quality=true
  Sample 2: value=3000, quality=true
```
