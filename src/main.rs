use node_handshake::message::{BitcoinMessage, Serializable};
use node_handshake::network::BitcoinNetwork;
use node_handshake::vv::{Command, VersionMessage};
use std::io::{Read, Result, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

fn perform_handshake() -> Result<()> {
    let sender = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18443);
    let receiver = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let user_agent = "/my-bitcoin-client:0.1.0/".to_string();

    // Establish a TCP connection to local Bitcoin node on port 18443
    let mut stream = TcpStream::connect(sender)?;

    // Create a version message using local regtest network parameters
    let version_message = VersionMessage::create(
        BitcoinNetwork::Regtest,
        receiver,
        sender,
        user_agent,
        0,
        false,
    )?;

    // println!("version_message {:?}", version_message);

    // Serialize the version message
    let serialized_version_msg = version_message.serialize()?;

    // println!("serialized_version_msg {:?}", serialized_version_msg);

    // Write the serialized version message to the TCP stream
    stream.write_all(&serialized_version_msg)?;
    stream.flush().unwrap();

    let mut resp_version_buffer = [0; 24];

    let _ = stream.read_exact(&mut resp_version_buffer);

    // println!("resp_version_buffer len(): {:?}", resp_version_buffer.len());

    // Create and send a verack message as an acknowledgment
    let verack_message = BitcoinMessage::new(Command::Verack, vec![], BitcoinNetwork::Regtest);
    let serialized_verack_msg = verack_message.serialize()?;
    stream.write_all(&serialized_verack_msg)?;
    stream.flush().unwrap();

    // println!("serialized_verack_msg {:?}", serialized_verack_msg);

    let mut resp_verack_buffer = [0; 24];

    let _ = stream.read_exact(&mut resp_verack_buffer);

    // println!("resp_verack_buffer len(): {:?}", resp_verack_buffer.len());

    Ok(())
}

fn main() -> Result<()> {
    // Perform basic handshake
    perform_handshake()
}
