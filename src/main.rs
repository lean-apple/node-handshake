use node_handshake::handshake::perform_handshake;
use node_handshake::network::BitcoinNetwork;
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn main() -> Result<(), Error> {
    // Example parameters for a simple handshake
    let sender = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let receiver = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
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
