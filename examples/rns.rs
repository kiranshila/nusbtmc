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
    let d = block_on(Device::open(VID, PID))?;
    println!("{d}");
    Ok(())
}
