// SPDX-License-Identifier: MIT OR Apache-2.0

use criterion::{
    criterion_group, criterion_main, AxisScale, BenchmarkId, Criterion, PlotConfiguration,
};
use rtp_types::RtpPacketBuilder;

fn default_builder<'a>() -> RtpPacketBuilder<&'a [u8], &'a [u8]> {
    RtpPacketBuilder::new()
        .payload_type(96)
        .ssrc(0x12345678)
        .sequence_number(0x100)
        .timestamp(0x200)
}

fn write_into_vec<'a>(builder: &RtpPacketBuilder<&'a [u8], &'a [u8]>, data: &mut Vec<u8>) {
    builder.write_into_vec(data).unwrap();
}

fn write_into_slice<'a>(builder: &RtpPacketBuilder<&'a [u8], &'a [u8]>, slice: &mut [u8]) {
    builder.write_into(slice).unwrap();
}

fn write_vec<'a>(builder: &RtpPacketBuilder<&'a [u8], &'a [u8]>) {
    let _data = builder.write_vec().unwrap();
}

fn bench_write(c: &mut Criterion) {
    let payload16 = [1; 16];
    let payload256 = [2; 256];
    let payload1280 = [3; 1280];
    let payload65280 = [4; 65280];

    let builders = [
        ("Header", default_builder()),
        ("CSRC", default_builder().add_csrc(0x081726354)),
        (
            "CSRC15",
            default_builder()
                .add_csrc(0x0)
                .add_csrc(0x1)
                .add_csrc(0x2)
                .add_csrc(0x3)
                .add_csrc(0x4)
                .add_csrc(0x5)
                .add_csrc(0x6)
                .add_csrc(0x7)
                .add_csrc(0x8)
                .add_csrc(0x9)
                .add_csrc(0xa)
                .add_csrc(0xb)
                .add_csrc(0xc)
                .add_csrc(0xd)
                .add_csrc(0xe),
        ),
        (
            "Extension",
            default_builder().extension(0x2345, payload16.as_slice()),
        ),
        ("Payload16", default_builder().payload(payload16.as_slice())),
        (
            "Payload256",
            default_builder().payload(payload256.as_slice()),
        ),
        (
            "Payload1280",
            default_builder().payload(payload1280.as_slice()),
        ),
        (
            "Payload65280",
            default_builder().payload(payload65280.as_slice()),
        ),
    ];

    let mut group = c.benchmark_group("Packet/WriteIntoVec");
    for (name, builder) in builders.iter() {
        let empty_vec = vec![];

        let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
        group.plot_config(plot_config);

        group.throughput(criterion::Throughput::Bytes(
            builder.calculate_size().unwrap() as u64,
        ));

        group.bench_with_input(BenchmarkId::from_parameter(name), builder, |b, builder| {
            b.iter_batched_ref(
                || empty_vec.clone(),
                |data| write_into_vec(builder, data),
                criterion::BatchSize::LargeInput,
            )
        });
    }
    group.finish();

    let mut group = c.benchmark_group("Packet/WriteIntoSlice");
    for (name, builder) in builders.iter() {
        let len = builder.calculate_size().unwrap();
        let slice_mut = vec![0; len];

        let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
        group.plot_config(plot_config);

        group.throughput(criterion::Throughput::Bytes(len as u64));

        group.bench_with_input(BenchmarkId::from_parameter(name), builder, |b, builder| {
            b.iter_batched_ref(
                || slice_mut.clone(),
                |slice| write_into_slice(builder, slice),
                criterion::BatchSize::LargeInput,
            )
        });
    }
    group.finish();

    let mut group = c.benchmark_group("Packet/WriteVec");
    for (name, builder) in builders.iter() {
        let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
        group.plot_config(plot_config);

        group.throughput(criterion::Throughput::Bytes(
            builder.calculate_size().unwrap() as u64,
        ));

        group.bench_with_input(BenchmarkId::from_parameter(name), builder, |b, builder| {
            b.iter(|| write_vec(builder))
        });
    }
    group.finish();
}

criterion_group!(packet_parse, bench_write);
criterion_main!(packet_parse);
