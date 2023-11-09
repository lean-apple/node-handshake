use node_handshake::messages::{BitcoinMessage, Serializable};
use node_handshake::network::BitcoinNetwork;
use node_handshake::vv::{Command, VersionMessage};
use std::io::{Error, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

/// Establish a TCP connection to a Bitcoin node for one of its network
/// Performs the initial handshake protocol by exchanging version and verack messages
/// Parameters
/// network - network type between Mainnet, Testnet3 and Regtest
/// sender - sending node's socket address
/// receiver - receiving node's socket address
/// user_agent - user agent's string
/// start_height - node's block height
pub fn perform_handshake(
    network: BitcoinNetwork,
    sender: SocketAddr,
    receiver: SocketAddr,
    user_agent: String,
    start_height: i32,
) -> Result<(), Error> {
    // Establish a TCP connection to local Bitcoin node on port 18443
    let mut stream = TcpStream::connect(sender)?;

    // Create a version message using local regtest network parameters
    let version_message =
        VersionMessage::create(network, receiver, sender, user_agent, start_height, false)?;

    // Serialize the version message
    let serialized_version_msg = version_message.serialize()?;

    // Write the serialized version message to the TCP stream
    stream.write_all(&serialized_version_msg)?;
    stream.flush().unwrap();

    let mut resp_version_buffer = [0; 24];

    let _ = stream.read_exact(&mut resp_version_buffer);

    // Create and send a verack message as an acknowledgment
    let verack_message = BitcoinMessage::new(Command::Verack, vec![], BitcoinNetwork::Regtest);
    let serialized_verack_msg = verack_message.serialize()?;
    stream.write_all(&serialized_verack_msg)?;
    stream.flush().unwrap();

    let mut resp_verack_buffer = [0; 24];

    let _ = stream.read_exact(&mut resp_verack_buffer);

    Ok(())
}

fn main() -> Result<(), Error> {
    // Example parameters for a simple handshake
    let sender = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18443);
    let receiver = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let user_agent = "/my-bitcoin-client:0.1.0/".to_string();
    let start_height = 0;

    // Perform basic handshake for regtest network
    perform_handshake(
        BitcoinNetwork::Regtest,
        sender,
        receiver,
        user_agent,
        start_height,
    )?;
    Ok(())
}
