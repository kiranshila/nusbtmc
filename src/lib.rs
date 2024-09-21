use bitflags::bitflags;
use nusb::{
    transfer::{ControlIn, ControlOut, ControlType, Recipient},
    Interface,
};

pub struct Device {
    interface: nusb::Interface,
    supports_488: bool,
    interface_capabilities: InterfaceCapabilities,
    device_capabilities: DeviceCapabilities,
    vendor: Option<String>,
    product: Option<String>,
    serial: Option<String>,
    tag: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Requested vid/pid device was not found or did not support USBTMC")]
    DeviceNotFound,
    #[error("Lower-level USB driver error")]
    Driver(#[from] nusb::Error),
    #[error("Error encountered during USB transfer")]
    Transfer(#[from] nusb::transfer::TransferError),
    #[error("USBTMC control request returned a non-success status: {0:#?}")]
    Control(ControlStatus),
}

pub type Result<T> = std::result::Result<T, Error>;

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
        let mut tmc_idx = None;
        let mut supports_488 = false;
        for i in di.interfaces() {
            if i.class() == INTERFACE_CLASS && i.subclass() == INTERFACE_SUBCLASS {
                tmc_idx = Some(i.interface_number());
                if i.protocol() == INTERFACE_PROTO_488 {
                    supports_488 = true;
                } else if i.protocol() != INTERFACE_PROTO_TMC {
                    return Err(Error::DeviceNotFound);
                }
            }
        }
        let tmc_idx = tmc_idx.ok_or(Error::DeviceNotFound)?;
        let interface = di.open()?.detach_and_claim_interface(tmc_idx)?;

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
        })
    }
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "USBTMC Device: {} PN:{} SN:{}",
            self.vendor.clone().unwrap_or_default(),
            self.product.clone().unwrap_or_default(),
            self.serial.clone().unwrap_or_default()
        )
    }
}

// ---------- Control Endpoints

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// Values to assign to bRequest
enum ControlRequest {
    /// Aborts a Bulk-OUT transfer
    InitiateAbortBulkOut = 1,
    /// Returns the status of the previously sent InitiateAbortBulkOut request
    CheckAbortBulkOutStatus = 2,
    /// Aborts a Bulk-IN transfer
    InitiateAbortBulkIn = 3,
    /// Returns the status of the previously sent InitiateAbortBulkInt request
    CheckAbortBulkInStatus = 4,
    /// Clears all previously sent pending and unprocessed Bulk-OUT USBTMC message content and clears all pending Bulk-IN transfers
    InitiateClear = 5,
    /// Returns the status of the previously sent InitiateClear request
    CheckClearStatus = 6,
    /// Returns attributes and capabilities of the interface
    GetCapabilities = 7,
    /// A mechanism to turn on an activity indicator for identification purposes. The device indicates whether or not it supports this request in the GetCapabilities response packet
    IndicatorPulse = 64,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ControlStatus {
    _Reserved,
    /// Success
    Success,
    // ---- Generic Warnings
    /// This status is valid if a device has received a USBTMC split transaction CHECK_STATUS request and the request is still being processed
    Pending,
    // ---- 0x03-0x1F USBTMC Warnings
    UsbTmcWarning(u8),
    // ---- 0x20-0x3F Subclass Warnings
    SubclassWarning(u8),
    // ---- 0x40-0x7F VISA Warnings
    VisaWarning(u8),
    // ---- Generic Failures
    /// Failure, unspecified reason, and a more specific USBTMC_status is not defined
    Failed,
    TransferNotInProgress,
    SplitNotInProgress,
    SplitInProgress,
    // --- 0x84-0x9F USBTMC Failures
    UsbTmcFailure(u8),
    // --- 0xA0-0xBF Subclass Failures
    SubclassFailure(u8),
    // --- 0xC0-0xFF VISA Failures
    VisaFailure(u8),
}

impl From<ControlStatus> for u8 {
    fn from(value: ControlStatus) -> Self {
        match value {
            ControlStatus::_Reserved => 0x00,
            ControlStatus::Success => 0x01,
            ControlStatus::Pending => 0x02,
            ControlStatus::UsbTmcWarning(v) => v,
            ControlStatus::SubclassWarning(v) => v,
            ControlStatus::VisaWarning(v) => v,
            ControlStatus::Failed => 0x80,
            ControlStatus::TransferNotInProgress => 0x81,
            ControlStatus::SplitNotInProgress => 0x82,
            ControlStatus::SplitInProgress => 0x83,
            ControlStatus::UsbTmcFailure(v) => v,
            ControlStatus::SubclassFailure(v) => v,
            ControlStatus::VisaFailure(v) => v,
        }
    }
}

// Not TryFrom because every value has a distinct pair
impl From<u8> for ControlStatus {
    fn from(value: u8) -> Self {
        match value {
            0x00 => ControlStatus::_Reserved,
            0x01 => ControlStatus::Success,
            0x02 => ControlStatus::Pending,
            0x03..0x20 => ControlStatus::UsbTmcWarning(value),
            0x20..0x40 => ControlStatus::SubclassWarning(value),
            0x40..0x80 => ControlStatus::VisaWarning(value),
            0x80 => ControlStatus::Failed,
            0x81 => ControlStatus::TransferNotInProgress,
            0x82 => ControlStatus::SplitNotInProgress,
            0x83 => ControlStatus::SplitInProgress,
            0x84..0xA0 => ControlStatus::UsbTmcFailure(value),
            0xA0..0xC0 => ControlStatus::SubclassFailure(value),
            0xC0..=0xFF => ControlStatus::VisaFailure(value),
        }
    }
}

impl ControlStatus {
    /// Check if the interpretation of the status should be a failure
    pub fn is_failure(self) -> bool {
        u8::from(self) >= 0x80u8
    }

    /// Check if the interpretation of the status should be a warning
    pub fn is_warning(self) -> bool {
        (0x02 >= u8::from(self)) && (u8::from(self) >= 0x7F)
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct InterfaceCapabilities: u8 {
        /// The interface supports an IndicatorPulse request
        const IndicatorPulse = 0b00000100;
        /// The interface is talk-only
        const TalkOnly = 0b00000010;
        /// The interface is listen-only
        const ListenOnly = 0b00000001;
        // The source may set any bits
        const _ = !0;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DeviceCapabilities: u8 {
        /// The device supports ending a bulk-in transfer when a byte matches a specified termination
        const TermCharTransferEnd = 0b00000100;
        // The source may set any bits
        const _ = !0;
    }
}

/// Initiate a device->host control request with `N` data bytes (-1 from the spec as the status is always included)
async fn control_in_request<const N: usize>(
    interface: &Interface,
    req: ControlRequest,
    recipient: Recipient,
    value: u16,
    index: u16,
) -> Result<[u8; N]> {
    let resp = interface
        .control_in(ControlIn {
            control_type: ControlType::Class,
            recipient,
            request: req as u8,
            value,
            index,
            length: (N + 1) as u16,
        })
        .await
        .into_result()?;
    let status = ControlStatus::from(resp[0]);
    if !matches!(status, ControlStatus::Success) {
        Err(Error::Control(status))
    } else {
        Ok(resp[1..]
            .try_into()
            .expect("successful response but incomplete data?"))
    }
}

async fn get_capabilities(
    interface: &Interface,
) -> Result<(InterfaceCapabilities, DeviceCapabilities)> {
    let resp: [u8; 0x17] = control_in_request(
        interface,
        ControlRequest::GetCapabilities,
        Recipient::Interface,
        0x00,
        0x00,
    )
    .await?;
    let ic = InterfaceCapabilities::from_bits(resp[3]).expect("invalid flags");
    let dc = DeviceCapabilities::from_bits(resp[4]).expect("invalid_flags");
    Ok((ic, dc))
}

// ----- Bulk Out Endpoints

enum BulkOutMessage {
    /// Identify a transfer that sends a device-dependent command message from the host to the device
    DevDepMsgOut { transfer_size: u32, eom: bool },
    /// Identify the transfer as a USBTMC command message to the device,
    /// allowing the device to send a response message containing device-dependent message data bytes
    RequestDevDepMsgIn { transfer_size: u32, term_char: bool },
}
