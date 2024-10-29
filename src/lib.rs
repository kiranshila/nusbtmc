use bitflags::bitflags;
use nusb::{
    transfer::{
        self, ControlIn, ControlType, Direction, EndpointType, Queue, Recipient, RequestBuffer,
        ResponseBuffer,
    },
    Interface,
};

/// The opened USB TMC device
pub struct Device {
    interface: nusb::Interface,
    supports_488: bool,
    interface_capabilities: InterfaceCapabilities,
    device_capabilities: DeviceCapabilities,
    vendor: Option<String>,
    product: Option<String>,
    serial: Option<String>,
    tag: u8,
    max_packet_size: usize,
    /// Bulk-out addr
    bulk_out_endpoint: u8,
    /// Bulk-in addr
    bulk_in_endpoint: u8,
    /// Optional, as per the spec
    interrupt_endpoint: Option<u8>,
}

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
#[allow(unused)]
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

// ----- Bulk Endpoints

/// Size of the bulk transfer headers in bytes
const HEADER_SIZE: usize = 12;

#[derive(Debug)]
struct BulkMessageHeader {
    tag: u8,
    msg: BulkMessage,
}

#[derive(Debug)]
enum BulkMessage {
    /// Host to device device-dependent command message
    DevDepMsgOut { transfer_size: u32, eom: bool },
    /// Request the deivce to send a message to the bulk-in endpoint
    RequestDevDepMsgIn {
        transfer_size: u32,
        term_char: Option<u8>,
    },
    /// Device to host device-dependent data
    DevDepMsgIn {
        transfer_size: u32,
        term_char: bool,
        eom: bool,
    },
}

impl BulkMessage {
    fn msgid(&self) -> u8 {
        match self {
            BulkMessage::DevDepMsgOut { .. } => 0x01,
            BulkMessage::RequestDevDepMsgIn { .. } => 0x02,
            BulkMessage::DevDepMsgIn { .. } => 0x02,
        }
    }
}

impl BulkMessageHeader {
    fn pack(self) -> Vec<u8> {
        // Each bulk-out transfer must be 32-bit aligned
        // Generic header
        let mut payload = vec![self.msg.msgid(), self.tag, !self.tag, 0x00];
        match self.msg {
            BulkMessage::DevDepMsgOut { transfer_size, eom } => {
                payload.extend_from_slice(&transfer_size.to_le_bytes());
                payload.push(eom as u8);
                // Padding
                payload.append(&mut vec![0u8; 3]);
            }
            BulkMessage::RequestDevDepMsgIn {
                transfer_size,
                term_char,
            } => {
                payload.extend_from_slice(&transfer_size.to_le_bytes());
                payload.push((if term_char.is_some() { 1 } else { 0 }) << 1);
                payload.push(term_char.unwrap_or_default());
                // Padding
                payload.append(&mut vec![0u8; 2]);
            }
            // I don't think we have to implement this as only the device constructs these messages
            BulkMessage::DevDepMsgIn { .. } => unimplemented!(),
        }
        payload
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 12 {
            return Err(Error::BadData);
        }
        // Get the message id
        let msg_id = bytes[0];
        // Check the tag
        let tag = bytes[1];
        if !bytes[2] != tag {
            return Err(Error::BadData);
        }
        if bytes[3] != 0 {
            return Err(Error::BadData);
        }

        let msg = match msg_id {
            0x02 => {
                let transfer_size = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                let term_char = (bytes[8] & 1 << 1) != 0;
                let eom = (bytes[8] & 1) != 0;
                BulkMessage::DevDepMsgIn {
                    transfer_size,
                    term_char,
                    eom,
                }
            }
            _ => unimplemented!(),
        };

        Ok(BulkMessageHeader { tag, msg })
    }
}

impl Device {
    /// Increment the "tag" field when performing bulk-out transfers
    fn inc_tag(&mut self) {
        self.tag = if self.tag == 255 { 1 } else { self.tag + 1 };
    }

    async fn bulk_out(&mut self, data: Vec<u8>) -> Result<()> {
        self.interface
            .bulk_out(self.bulk_out_endpoint, data)
            .await
            .into_result()?;
        Ok(())
    }

    async fn bulk_in(&mut self) -> Result<Vec<u8>> {
        Ok(self
            .interface
            .bulk_in(
                self.bulk_in_endpoint,
                RequestBuffer::new(self.max_packet_size),
            )
            .await
            .into_result()?)
    }

    /// Write bytes to the connected device
    pub async fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        // Not supported on "talk-only" devices
        if self
            .interface_capabilities
            .contains(InterfaceCapabilities::TalkOnly)
        {
            return Err(Error::TalkOnly);
        }

        // There must be data
        if data.is_empty() {
            return Err(Error::EmptyWrite);
        }

        // Determine chunking size
        let padding = (4 - data.len() % 4) % 4;
        let transfer_size = data.len() + padding;

        // We will always enqueue all the bytes into one transfer, so EOM is always true
        // Transfer here being a sequece of bulk transfers starting with the USBTMC header
        let mut payload = BulkMessageHeader {
            tag: self.tag,
            msg: BulkMessage::DevDepMsgOut {
                transfer_size: transfer_size.try_into().unwrap(),
                eom: true,
            },
        }
        .pack();
        self.inc_tag();
        payload.extend_from_slice(data);
        payload.append(&mut vec![0u8; padding]);

        // Send out in chunks
        let mut boq = self.interface.bulk_out_queue(self.bulk_out_endpoint);
        for chunk in payload.chunks(self.max_packet_size) {
            debug_assert_eq!(
                0,
                chunk.len() % 4,
                "submitted chunks must be multiples of 4"
            );
            boq.submit(chunk.to_vec());
        }

        // Wait for all of those to flush
        while boq.pending() != 0 {
            let _ = boq.next_complete().await.into_result()?;
        }

        Ok(())
    }

    /// Write a string to the device
    pub async fn write<T: AsRef<str>>(&mut self, s: T) -> Result<()> {
        self.write_raw(s.as_ref().as_bytes()).await
    }

    /// Listen to bytes from the device
    ///
    /// NOTE: This will await forever if the device wasn't setup to send bytes
    pub async fn listen_raw(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![];

        // Request one chunk's worth of data, check the header and then decide:
        // 1. If transfer_size is contained within this chunk
        //    a. If eom is true - we're done!
        //    b. If eom is false, we need to totally start over reading a new header etc.
        // 2. Transfer size is *not* contained within this chunk
        //    b. request another chunk and *don't* parse a header, repeating until we capture transfer_size then decide EOM

        loop {
            let resp = self.bulk_in().await?;
            let hdr = BulkMessageHeader::try_from_bytes(&resp[0..HEADER_SIZE])?;
            if let BulkMessage::DevDepMsgIn {
                transfer_size, eom, ..
            } = hdr.msg
            {
                // Copy out everything
                buf.extend_from_slice(&resp[HEADER_SIZE..]);
                // Keep requesting data until we get all of transfer_size
                while buf.len() < transfer_size.try_into().unwrap() {
                    // Get another chunk
                    let mut resp = self.bulk_in().await?;
                    // Copy out all of this
                    buf.append(&mut resp);
                }

                // Now look at EOM since we have all the data of the transfer
                if eom {
                    break;
                }
            } else {
                return Err(Error::BadData);
            }
        }

        Ok(buf)
    }

    /// Listens for a string from the device
    ///
    /// NOTE: This will await forever if the device wasn't configured to send anything
    pub async fn listen(&mut self) -> Result<String> {
        let raw = self.listen_raw().await?;
        Ok(String::from_utf8(raw)?)
    }

    /// Explicitly read bytes from the device
    pub async fn read_raw(&mut self) -> Result<Vec<u8>> {
        // Not supported on "listen-only" devices
        if self
            .interface_capabilities
            .contains(InterfaceCapabilities::ListenOnly)
        {
            return Err(Error::ListenOnly);
        }

        let mut buf = vec![];

        loop {
            // Prepare request payload
            let payload = BulkMessageHeader {
                tag: self.tag,
                msg: BulkMessage::RequestDevDepMsgIn {
                    transfer_size: self.max_packet_size as u32,
                    term_char: None, //TODO: Fixme
                },
            }
            .pack();
            self.inc_tag();

            // Send it
            self.bulk_out(payload).await?;

            // Read the response
            let resp = self.bulk_in().await?;
            let hdr = BulkMessageHeader::try_from_bytes(&resp[0..HEADER_SIZE])?;
            if let BulkMessage::DevDepMsgIn {
                transfer_size, eom, ..
            } = hdr.msg
            {
                // Copy out everything
                buf.extend_from_slice(&resp[HEADER_SIZE..]);
                // Keep requesting data until we get all of transfer_size
                while buf.len() < transfer_size.try_into().unwrap() {
                    // Get another chunk
                    let mut resp = self.bulk_in().await?;
                    // Copy out all of this
                    buf.append(&mut resp);
                }

                // Now look at EOM since we have all the data of the transfer
                if eom {
                    break;
                }
            } else {
                return Err(Error::BadData);
            }
        }

        Ok(buf)
    }

    /// Explicitly request a string from the device
    pub async fn read(&mut self) -> Result<String> {
        let raw = self.read_raw().await?;
        Ok(String::from_utf8(raw)?)
    }

    /// Perform a query for bytes from the device
    pub async fn query_raw(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        // Write the bytes
        self.write_raw(data).await?;
        // Then read
        self.read_raw().await
    }

    /// Perform a query for a string from the device
    pub async fn query<T: AsRef<str>>(&mut self, s: T) -> Result<String> {
        self.write(s).await?;
        self.read().await
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn test_pack_dev_dep_msg_out() {
        let bytes = BulkMessageHeader {
            tag: 0xAD,
            msg: BulkMessage::DevDepMsgOut {
                transfer_size: 0xDE,
                eom: true,
            },
        }
        .pack();
        assert_eq!(vec![1, 0xAD, !0xAD, 0, 0xDE, 0, 0, 0, 1, 0, 0, 0], bytes);

        let bytes = BulkMessageHeader {
            tag: 0xAD,
            msg: BulkMessage::DevDepMsgOut {
                transfer_size: 0xDE,
                eom: false,
            },
        }
        .pack();
        assert_eq!(vec![1, 0xAD, !0xAD, 0, 0xDE, 0, 0, 0, 0, 0, 0, 0], bytes);
    }
}
