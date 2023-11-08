use super::network::BitcoinNetwork;
use super::utils::calculate_checksum;
use super::vv::Command;
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Error;

// Constants for the Bitcoin protocol
const COMMAND_SIZE: usize = 12;
// First 4 bytes of the double hash
pub const CHECKSUM_SIZE: usize = 4;

/// Trait for serializable Message structures
pub trait Serializable {
    fn serialize(&self) -> Result<Vec<u8>, Error>;
}

/// Bitcoin protocol message
/// Only two elements are stored in the struct
/// The other ones are get from the serialization
/// All the Bitcoin Message components are documented here
/// https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
#[derive(Debug, Clone)]
pub struct BitcoinMessage {
    // ASCII string identifying the packet content - holds the command of the message
    // Move to Vec<u8> for practicity
    pub command: Vec<u8>,
    // Bytes Vector that holds the data message
    pub payload: Vec<u8>,
    // Bitcoin network used for the message
    pub network: BitcoinNetwork,
}

impl BitcoinMessage {
    pub fn new(command: Command, payload: Vec<u8>, network: BitcoinNetwork) -> Self {
        let mut command_v = Vec::with_capacity(COMMAND_SIZE);
        command_v.extend_from_slice(command.as_bytes());
        command_v.resize(COMMAND_SIZE, 0);
        Self {
            command: command_v,
            payload,
            network,
        }
    }
}

impl Serializable for BitcoinMessage {
    /// Serialize the Bitcoin message to a byte vector
    /// Append the magic value, command, payload size, checksum, and payload
    /// to a byte vector which represents the serialized message
    fn serialize(&self) -> Result<Vec<u8>, Error> {
        // Calculated the total size to avoid reallocation
        // let total_payload_size = COMMAND_SIZE + 4 + CHECKSUM_SIZE + self.payload.len();
        // let mut message = Vec::with_capacity(total_payload_size);

        let mut message = Vec::new();
        // Add the network magic key first
        message.extend(self.network.magic());

        // Add the network magic key first
        message.extend(&self.command);

        let payload_size = self.payload.len();
        message.write_u32::<LittleEndian>(payload_size as u32)?;

        let checksum = calculate_checksum(self.payload.clone());
        message.extend(checksum);

        message.extend(&self.payload);

        Ok(message)
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
        let command_bytes = Command::Version.as_bytes();
        let mut command_fixed_size = [0u8; COMMAND_SIZE];
        for (item, &byte) in command_bytes.iter().enumerate() {
            command_fixed_size[item] = byte;
        }
        for item in command_fixed_size.iter_mut().skip(command_bytes.len()) {
            *item = 0;
        }
        assert_eq!(&serialized_msg[4..4 + COMMAND_SIZE], &command_fixed_size);

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
        // Parameters for the version message
        let network = BitcoinNetwork::Testnet3;
        let add_recv = SocketAddr::from_str("127.0.0.1:8333").unwrap();
        let add_from = SocketAddr::from_str("127.0.0.1:8333").unwrap();
        let user_agent = "/rust-bitcoin:0.1/".to_string();
        let start_height = 0;
        let relay = false;

        // Create a dummy payload and its related message from the command
        let payload = vec![0xef, 0xab, 0xef, 0xdf];

        BitcoinMessage::new(Command::Version, payload.clone(), BitcoinNetwork::Testnet3);

        let version_message =
            VersionMessage::create(network, add_recv, add_from, user_agent, start_height, relay)
                .expect("Version Bitcoin Message could not be created");

        let serialized_msg = version_message
            .serialize()
            .expect("Version Message could not be serialized");

        // Check that the magic number is correct for Testnet3
        assert_eq!(&serialized_msg[0..4], &network.magic());
    }
}
