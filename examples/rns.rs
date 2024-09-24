use futures_lite::future::block_on;
use nusbtmc::Device;

const VID: u16 = 0x0aad;
const PID: u16 = 0x0151;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    // Setup the device
    let mut d = block_on(Device::open(VID, PID)).unwrap();
    println!("{d}");
    // Perform a query
    let bytes = block_on(async {
        d.write_raw("*RST".as_bytes()).await.unwrap();
        d.write_raw("INIT".as_bytes()).await.unwrap();
        d.query_raw("FETCH?".as_bytes()).await
    })?;
    let s = String::from_utf8(bytes).unwrap();
    dbg!(s);
    Ok(())
}
