// SPDX-License-Identifier: MIT OR Apache-2.0

use criterion::{
    criterion_group, criterion_main, AxisScale, BenchmarkId, Criterion, PlotConfiguration,
};
use rtp_types::RtpPacket;

static ONLY_HEADER: [u8; 12] = [
    0x80, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
];

static SINGLE_CSRC: [u8; 16] = [
    0x81, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14,
];
static EXTENSION: [u8; 20] = [
    0x90, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x00, 0x1,
    0x0d, 0x0e, 0x0f, 0x10,
];
static PADDING: [u8; 16] = [
    0xa0, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x00, 0x02,
];

fn parse(data: &[u8]) {
    let _rtp = RtpPacket::parse(data).unwrap();
}

fn bench_parse(c: &mut Criterion) {
    let payload16 = [1; 16];
    let payload256 = [2; 256];
    let payload1280 = [3; 1280];
    let payload65280 = [4; 65280];

    let rtp16 = ONLY_HEADER.into_iter().chain(payload16).collect::<Vec<_>>();
    let rtp256 = ONLY_HEADER
        .into_iter()
        .chain(payload256)
        .collect::<Vec<_>>();
    let rtp1280 = ONLY_HEADER
        .into_iter()
        .chain(payload1280)
        .collect::<Vec<_>>();
    let rtp65280 = ONLY_HEADER
        .into_iter()
        .chain(payload65280)
        .collect::<Vec<_>>();

    let packet_data = [
        ("Header", ONLY_HEADER.as_slice()),
        ("CSRC", SINGLE_CSRC.as_slice()),
        ("Extension", EXTENSION.as_slice()),
        ("Padding", PADDING.as_slice()),
        ("Payload16", rtp16.as_slice()),
        ("Payload256", rtp256.as_slice()),
        ("Payload1280", rtp1280.as_slice()),
        ("Payload65280", rtp65280.as_slice()),
    ];

    let mut group = c.benchmark_group("Packet/Parse");
    for (name, data) in packet_data {
        let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
        group.plot_config(plot_config);

        group.throughput(criterion::Throughput::Bytes(data.len() as u64));

        group.bench_with_input(BenchmarkId::from_parameter(name), &data, |b, data| {
            b.iter(|| parse(data))
        });
    }
    group.finish();
}

criterion_group!(packet_parse, bench_parse);
criterion_main!(packet_parse);
