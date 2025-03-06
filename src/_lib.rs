//! Spec-compliant implementation of the USBTMC spec, following the implementation in the linux kernel

use bitflags::bitflags;
use nusb::{
    transfer::{
        self, ControlIn, ControlType, Direction, EndpointType, Queue, Recipient, RequestBuffer,
        ResponseBuffer,
    },
    Interface,
};

const HEADER_SIZE: usize = 12;
/// Minimum USB timeout (in milliseconds)
const MIN_TIMEOUT: u32 = 100;
/// Default USB timeout (in milliseconds)
const TIMEOUT: u32 = 5000;

/// Max number of URBs used in write transfers
const MAX_URBS_IN_FLIGHT: usize = 16;
/// IO buffer size used in generic read/write functions
const BUFSIZE: usize = 4096;

/// Maximum number of read cycles to empty bulk-in endpoint during
/// CLEAR and ABORT_BULK_IN requests. Prevents us from awaiting forever.
const MAX_READS_TO_CLEAR_BULK_IN: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Tried to write no data")]
    EmptyWrite,
    #[error("Requested vid/pid device was not found or did not support USBTMC")]
    DeviceNotFound,
    #[error("Tried to write data to a `talk-only` device")]
    TalkOnly,
    #[error("Tried to ask for data from a `listen-only` device")]
    ListenOnly,
    #[error("Lower-level USB driver error")]
    Driver(#[from] nusb::Error),
    #[error("Error encountered during USB transfer")]
    Transfer(#[from] nusb::transfer::TransferError),
    #[error("USBTMC control request returned a non-success status: {0:#?}")]
    Control(ControlStatus),
    #[error("USB device is unconfigured")]
    Unconfigured(#[from] nusb::descriptors::ActiveConfigurationError),
    #[error("Returned data was invalid")]
    BadData,
    #[error("Returned string was not valid UTF8")]
    BadString(#[from] std::string::FromUtf8Error),
}

#[allow(non_snake_case)]
pub struct Device {
    // The nusb interface itself
    interface: nusb::Interface,

    // Endpoint addresses
    bulk_in: u8,
    bulk_out: u8,

    // tags and state needed for abort
    bTag: u8,
    bTag_last_write: u8,
    bTag_last_read: u8,

    // packet size of IN bulk
    wMaxPacketSize: u16,
}

// ---------- Interface Descriptor

const INTERFACE_CLASS: u8 = 0xFE; // "Application-Class"
const INTERFACE_SUBCLASS: u8 = 0x03; // "USBTMC"
const INTERFACE_PROTO_TMC: u8 = 0x00; // Vanilla USBTMC
const INTERFACE_PROTO_488: u8 = 0x01; // USB488 subclass

impl Device {
    pub async fn open(vid: u16, pid: u16) -> Result<Self> {
        // Find the interface which matches the expected interface descriptor
        let di = nusb::list_devices()
            .unwrap()
            .find(|dev| dev.vendor_id() == vid && dev.product_id() == pid)
            .ok_or(Error::DeviceNotFound)?;
        let device = di.open()?;

        let configuration = device.active_configuration()?;

        let mut supports_488 = false;
        let mut tmc_idx = None;
        let mut bulk_out = None;
        let mut bulk_in = None;
        let mut interrupt_endpoint = None;
        let mut max_size = None;
        for i in configuration.interfaces() {
            for alt in i.alt_settings() {
                if alt.class() == INTERFACE_CLASS && alt.subclass() == INTERFACE_SUBCLASS {
                    tmc_idx = Some(i.interface_number());
                    if alt.protocol() == INTERFACE_PROTO_488 {
                        supports_488 = true;
                    } else if alt.protocol() != INTERFACE_PROTO_TMC {
                        return Err(Error::DeviceNotFound);
                    }
                    for endpoint in alt.endpoints() {
                        let dir = endpoint.direction();
                        let tt = endpoint.transfer_type();
                        let ms = endpoint.max_packet_size();
                        let addr = endpoint.address();
                        match (dir, tt) {
                            (Direction::In, EndpointType::Bulk) => {
                                bulk_in = Some(addr);
                                max_size = Some(ms);
                            }
                            (Direction::Out, EndpointType::Bulk) => {
                                bulk_out = Some(addr);
                            }
                            (Direction::In, EndpointType::Interrupt) => {
                                interrupt_endpoint = Some(addr);
                            }
                            _ => (),
                        }
                    }
                }
            }
        }

        // The spec requires exactly two bulk enpoints for the interface and an optional interrupt
        let bulk_out_endpoint = bulk_out.ok_or(Error::DeviceNotFound)?;
        let bulk_in_endpoint = bulk_in.ok_or(Error::DeviceNotFound)?;
        let max_packet_size = max_size.unwrap();

        let interface = device.detach_and_claim_interface(tmc_idx.ok_or(Error::DeviceNotFound)?)?;

        let product = di.product_string();
        let vendor = di.manufacturer_string();
        let serial = di.serial_number();

        let (interface_capabilities, device_capabilities) = get_capabilities(&interface).await?;

        Ok(Self {
            interface,
            supports_488,
            interface_capabilities,
            device_capabilities,
            product: product.map(str::to_string),
            vendor: vendor.map(str::to_string),
            serial: serial.map(str::to_string),
            tag: 1,
            max_packet_size,
            bulk_out_endpoint,
            bulk_in_endpoint,
            interrupt_endpoint,
        })
    }
}
