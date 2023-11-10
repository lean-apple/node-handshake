use super::messages::{Serializable, CHECKSUM_SIZE, COMMAND_SIZE};
use super::network::{add_serialize_addr, read_deserialized_add, BitcoinNetwork};
use super::utils::{calculate_checksum, calculate_timestamp, generate_nonce};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Error, ErrorKind, Read};
use std::net::SocketAddr;

// Constants for the Bitcoin protocol
const PROTOCOL_VERSION: i32 = 70001i32;
// Service contanst that corresponds to a full node that can serve the full blockchain
const NODE_NETWORK_SERVICE: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command {
    // Message used when two nodes first connect
    Version,
    // Response message sent after a version message
    Verack,
}

impl Command {
    pub fn as_str(&self) -> &str {
        match self {
            Command::Version => "version",
            Command::Verack => "verack",
        }
    }
    // Return specific fixed-size bytes array for
    pub fn as_fixed_length_vec(&self) -> Result<[u8; COMMAND_SIZE], Error> {
        let bytes = self.as_str().as_bytes();
        if bytes.len() > COMMAND_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Command string is too long",
            ));
        }
        let mut command_fixed: [u8; COMMAND_SIZE] = [0; COMMAND_SIZE];
        for (i, &byte) in bytes.iter().enumerate() {
            command_fixed[i] = byte;
        }

        Ok(command_fixed)
    }
}

/// Version message used for a first connection between nodes
/// Referred to Bitcoin documentation
/// https://en.bitcoin.it/wiki/Protocol_documentation#version
#[derive(Debug)]
pub struct VersionMessage {
    // Highest Bitcoin protocol version the node can use
    version: i32,
    // Bitmask describing the services supported by the node
    services: u64,
    // Timestamp recording the message creation
    timestamp: i64,
    // Node's address receiving the version message
    receiver: SocketAddr,
    // Node's address initializing the connection
    sender: SocketAddr,
    // Random nonce to detection connection to self
    nonce: u64,
    // Software running on the node
    _user_agent: String,
    // Highest block number
    start_height: i32,
    // Indicated if the node wants to receive relayed transactions
    relay: bool,
}

impl VersionMessage {
    pub fn new(
        receiver: SocketAddr,
        sender: SocketAddr,
        _user_agent: String,
        start_height: i32,
        relay: bool,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK_SERVICE,
            timestamp: calculate_timestamp(),
            receiver,
            sender,
            nonce: generate_nonce(),
            _user_agent,
            start_height,
            relay,
        }
    }
}

impl Serializable for VersionMessage {
    // Serialize VersionMessage to bytes to be send to node
    fn serialize(&self) -> Result<Vec<u8>, Error> {
        let mut message = Vec::new();

        // Constructing the payload adding all version message elements
        message.extend(&self.version.to_le_bytes());
        message.extend(&self.services.to_le_bytes());
        message.extend(&self.timestamp.to_le_bytes());

        // Serialize the receiver node's (remote peer's) network address
        add_serialize_addr(&mut message, self.services, &self.receiver)?;

        // Serialize this sender node's network address
        add_serialize_addr(&mut message, self.services, &self.sender)?;

        // Add nonce to the payload
        message.write_u64::<LittleEndian>(self.nonce)?;
        // Allocation for the user agent
        message.extend(&[0]);
        message.write_i32::<LittleEndian>(self.start_height)?;
        message.write_u8(self.relay as u8)?;
        // Allocation for the relay
        message.extend(&[0]);
        Ok(message)
    }

    // Deserialization used to verify the response content
    fn deserialize(msg: Vec<u8>) -> Result<Box<Self>, Error> {
        let mut cursor = Cursor::new(msg);

        let version = cursor.read_i32::<LittleEndian>()?;
        if version < PROTOCOL_VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Unsupported protocol version",
            ));
        }

        let services = cursor.read_u64::<LittleEndian>()?;
        let timestamp = cursor.read_i64::<LittleEndian>()?;

        let receiver = read_deserialized_add(&mut cursor)?;
        let sender = read_deserialized_add(&mut cursor)?;

        let user_agent_byte = cursor.read_u8()?;

        let nonce = cursor.read_u64::<LittleEndian>()?;
        let start_height = cursor.read_i32::<LittleEndian>()?;
        let relay = cursor.read_u8()? > 0;

        Ok(Box::new(VersionMessage {
            version,
            services,
            timestamp,
            receiver,
            sender,
            nonce,
            _user_agent: user_agent_byte.to_string(),
            start_height,
            relay,
        }))
    }
}

/// Verack Message sent in response to a Version message
/// More information https://en.bitcoin.it/wiki/Protocol_documentation#verack
#[derive(Debug, PartialEq)]
pub struct VerackMessage {
    // Magic Key for the Bitcoin network
    magic: u32,
    // ASCII string identifying the packet content - holds the command of the message
    command: [u8; 12],
    // Potential argument of verack message
    length: u32,
    // Potential argument of verack message
    checksum: u32,
}

impl VerackMessage {
    // Create Verack Message with Version message parameters
    pub fn new(network: BitcoinNetwork, resp_command: Command) -> Self {
        let command = resp_command
            .as_fixed_length_vec()
            .expect("Complete and convert command size");
        Self {
            magic: network.as_u32(),
            command,
            length: 0,
            checksum: u32::from_ne_bytes(calculate_checksum([].to_vec())),
        }
    }
    /// Help to deserialize verack message answer
    /// Veirfy magic number and Command that was originally sent
    pub fn deserialize_and_verify(
        msg: Vec<u8>,
        network: BitcoinNetwork,
        resp_command: Command,
    ) -> Result<Self, Error> {
        let mut cursor = Cursor::new(msg.clone());

        // Check the magic number
        let magic = cursor.read_u32::<LittleEndian>()?;
        if magic != network.as_u32() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid magic number in verack response",
            ));
        }

        // Read and check the command that was sent
        let mut command = [0u8; COMMAND_SIZE];
        cursor.read_exact(&mut command)?;
        let verack_command = resp_command
            .as_fixed_length_vec()
            .expect("Complete and convert command size");
        if command != verack_command {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid command in verack response",
            ));
        };

        let length = cursor.read_u32::<LittleEndian>()?;

        // Read the checksum
        // Impossible to check on which payload it was used
        let mut checksum = [0u8; CHECKSUM_SIZE];
        cursor.read_exact(&mut checksum)?;

        Ok(VerackMessage {
            magic,
            command,
            length,
            checksum: u32::from_ne_bytes(checksum),
        })
    }
}
