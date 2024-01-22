#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(packet) = rtp_types::RtpPacket::parse(data) {
        let built = packet.as_builder().write_vec().unwrap();
        if let Some(padding) = packet.padding() {
            // ignore any padding as its contents in the original data are undefined
            assert_eq!(&built[..built.len() - padding as usize], &data[..data.len() - padding as usize]);
        } else {
            assert_eq!(&built, &data);
        }
    }
});
