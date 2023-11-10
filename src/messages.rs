use super::network::BitcoinNetwork;
use super::utils::calculate_checksum;
use super::vv::Command;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Error, ErrorKind, Read};

// Constants for the Bitcoin protocol
pub const COMMAND_SIZE: usize = 12;
// First 4 bytes of the double hash
pub const CHECKSUM_SIZE: usize = 4;

/// Trait for serializable Message structures
pub trait Serializable {
    fn serialize(&self) -> Result<Vec<u8>, Error>;
    fn deserialize(msg: Vec<u8>) -> Result<Box<Self>, Error>;
}

/// Bitcoin protocol message
/// Only two elements are stored in the struct
/// The other ones are get from the serialization
/// All the Bitcoin Message components are documented here
/// https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
#[derive(Debug, Clone)]
pub struct BitcoinMessage {
    // Magic Key for the Bitcoin network
    magic: u32,
    // ASCII string identifying the packet content - holds the command of the message
    command: [u8; 12],
    // Payload Length
    length: u32,
    // First 4 bytes of double Hash of payload
    checksum: u32,
    // Bytes Vector that holds the data message
    payload: Vec<u8>,
}

impl BitcoinMessage {
    pub fn new(command: Command, payload: Vec<u8>, network: BitcoinNetwork) -> Self {
        let command = command
            .as_fixed_length_vec()
            .expect("Complete and convert command size");

        let payload_length = payload.len();
        let checksum = calculate_checksum(payload.clone());
        Self {
            magic: network.as_u32(),
            command,
            length: payload_length as u32,
            checksum: u32::from_ne_bytes(checksum),
            payload,
        }
    }
}

impl Serializable for BitcoinMessage {
    /// Serialize the Bitcoin message to a byte vector
    /// Append the magic value, command, payload size, checksum, and payload
    /// to a byte vector which represents the serialized message
    fn serialize(&self) -> Result<Vec<u8>, Error> {
        let mut message = Vec::new();

        // Add all bitcoin message keys to vec
        message.write_u32::<LittleEndian>(self.magic)?;

        message.extend(&self.command);
        message.write_u32::<LittleEndian>(self.length)?;
        message.write_u32::<LittleEndian>(self.checksum)?;
        message.extend(&self.payload);

        Ok(message)
    }
    fn deserialize(msg: Vec<u8>) -> Result<Box<Self>, Error> {
        let mut cursor = Cursor::new(msg);

        // Check the magic number
        let magic = cursor.read_u32::<LittleEndian>()?;

        // Read the command
        let mut command = vec![0u8; COMMAND_SIZE];
        cursor.read_exact(&mut command)?;

        let mut command_v = Vec::with_capacity(COMMAND_SIZE);
        command_v.extend(&command);
        command_v.resize(COMMAND_SIZE, 0);

        // Read the payload size
        let payload_size = cursor.read_u32::<LittleEndian>()? as usize;

        // Read the checksum
        let mut checksum = [0u8; CHECKSUM_SIZE];
        cursor.read_exact(&mut checksum)?;

        // Read the payload
        let mut payload = vec![0u8; payload_size];
        cursor.read_exact(&mut payload)?;

        // Verify the checksum
        let calculated_checksum = calculate_checksum(payload.clone());
        if checksum != calculated_checksum {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid checksum"));
        }

        Ok(Box::new(BitcoinMessage {
            magic,
            length: payload_size as u32,
            command: command_v.try_into().unwrap(),
            checksum: u32::from_ne_bytes(checksum),
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::vv::VersionMessage;
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[test]
    fn test_serializating_message_ok() {
        // Create a dummy payload and its related message from the command
        let payload = vec![0xef, 0xab, 0xef, 0xdf];
        let message =
            BitcoinMessage::new(Command::Version, payload.clone(), BitcoinNetwork::Testnet3);
        let serialized_msg = message
            .serialize()
            .expect("Bitcoin message could not be serialized");

        // Check magic value
        assert_eq!(&serialized_msg[0..4], &BitcoinNetwork::Testnet3.magic());

        // Check command
        let command_bytes = Command::Version
            .as_fixed_length_vec()
            .expect("Complete and convert command size");
        assert_eq!(&serialized_msg[4..4 + COMMAND_SIZE], &command_bytes);

        // Checks payload size
        assert_eq!(
            &serialized_msg[16..20],
            &(payload.len() as u32).to_le_bytes()
        );

        // Verifies data integrity ie. checksum
        assert_eq!(&serialized_msg[20..24], &calculate_checksum(payload));
    }

    #[test]
    fn test_create_version_message_ok() {
        // Parameters for the version message on Testnet3 network
        let network = BitcoinNetwork::Testnet3;
        let add_recv =
            SocketAddr::from_str("127.0.0.1:18333").expect("Failed to convert to socket address");
        let add_from =
            SocketAddr::from_str("127.0.0.1:18334").expect("Failed to convert to socket address");
        let user_agent = "/rust-bitcoin:0.1/".to_string();
        let start_height = 0;
        let relay = false;

        let version_message =
            VersionMessage::new(add_recv, add_from, user_agent, start_height, relay);

        let payload = version_message
            .serialize()
            .expect("Failed to serialized version message");
        let bitcoin_message = BitcoinMessage::new(Command::Version, payload, network);
        let serialized_msg = bitcoin_message
            .serialize()
            .expect("Bitcoin Message could not be serialized");

        // Check that the magic number is correct for Testnet3
        assert_eq!(&serialized_msg[0..4], &network.magic());
    }

    #[test]
    fn test_serialization_and_deserialization_ok() {
        let network = BitcoinNetwork::Testnet3;
        let add_recv =
            SocketAddr::from_str("127.0.0.1:18333").expect("Failed to convert to socket address");
        let add_from =
            SocketAddr::from_str("127.0.0.1:18334").expect("Failed to convert to socket address");
        let user_agent = "/rust-bitcoin:0.1/".to_string();
        let start_height = 0;
        let relay = false;

        let version_message =
            VersionMessage::new(add_recv, add_from, user_agent, start_height, relay);

        let payload = version_message
            .serialize()
            .expect("Failed to serialized version message");
        let bitcoin_message = BitcoinMessage::new(Command::Version, payload.clone(), network);
        let serialized_msg = bitcoin_message
            .serialize()
            .expect("Bitcoin Message could not be serialized");

        let deserialized_msg = BitcoinMessage::deserialize(serialized_msg)
            .expect("Failed to deserialized Bitcoin message");
        assert_eq!(&deserialized_msg.magic, &network.as_u32());
        assert_eq!(deserialized_msg.length as usize, payload.len());
        assert_eq!(deserialized_msg.payload, payload);
    }
}
