#[cfg(test)]
mod tests {
    use node_handshake::handshake::perform_handshake;
    use node_handshake::network::BitcoinNetwork;
    use std::io::ErrorKind;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::str::FromStr;

    // These tests are supposed to be run in parallel with a bitcoin node
    // Depending on the network chosen
    // Here Regtest Network is picked

    #[test]
    // Basically same test than in main
    fn test_perform_handshake_ok() {
        let sender = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let receiver = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let user_agent = "/test-bitcoin-client:0.1.0/".to_string();
        let start_height = 0;
        let res_handshake = perform_handshake(
            BitcoinNetwork::Regtest,
            sender,
            receiver,
            user_agent,
            start_height,
        );

        assert!(res_handshake.is_ok(), "Handshake should succeed");
    }

    #[test]
    // Check the connection is refused for an uncorrect IP
    fn test_perform_handshake_error_wrong_ip() {
        let add_rec =
            SocketAddr::from_str("127.0.0.1:1899").expect("Failed to convert to socket address");
        let wrong_sender_add =
            SocketAddr::from_str("127.0.0.1:9334").expect("Failed to convert to socket address");

        let user_agent = "/test-bitcoin-client:0.1.0/".to_string();

        let result = perform_handshake(
            BitcoinNetwork::Regtest,
            add_rec,
            wrong_sender_add,
            user_agent,
            0,
        );

        assert!(
            result.is_err(),
            "Handshake should fail due to connection error"
        );
        assert_eq!(result.unwrap_err().kind(), ErrorKind::ConnectionRefused);
    }
}
