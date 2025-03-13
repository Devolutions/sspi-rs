use dpapi::client::{ConnectionOptions, ConnectionUrlParseError, WebAppAuth};
use dpapi::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use url::Url;

const DEFAULT_PORT: u16 = 135;

#[test]
fn test_tcp_url_without_scheme_parse() {
    let url = "127.0.0.1";

    let options = ConnectionOptions::parse(url, DEFAULT_PORT).unwrap();

    let expected = ConnectionOptions::Tcp(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(127, 0, 0, 1),
        DEFAULT_PORT,
    )));
    assert_eq!(expected, options);
}

#[test]
fn test_tcp_url_with_scheme_parse() {
    let url = "tcp://127.0.0.1";

    let options = ConnectionOptions::parse(url, DEFAULT_PORT).unwrap();

    let expected = ConnectionOptions::Tcp(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(127, 0, 0, 1),
        DEFAULT_PORT,
    )));
    assert_eq!(expected, options);
}

#[test]
fn test_websocket_tunnel_url_parse() {
    let url = "ws://192.168.0.1:1234/path/path2,tcp://127.0.0.1";

    let options = ConnectionOptions::parse(url, DEFAULT_PORT).unwrap();

    let expected = ConnectionOptions::WebSocketTunnel {
        websocket_url: Url::parse("ws://192.168.0.1:1234/path/path2").unwrap(),
        web_app_auth: WebAppAuth::None,
        tcp_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), DEFAULT_PORT)),
    };
    assert_eq!(expected, options);
}

#[test]
fn test_websocket_tunnel_url_tcp_url_first_parse() {
    let url = "tcp://127.0.0.1, ws://192.168.0.1:1234/path/path2";

    let options = ConnectionOptions::parse(url, DEFAULT_PORT).unwrap();

    let expected = ConnectionOptions::WebSocketTunnel {
        websocket_url: Url::parse("ws://192.168.0.1:1234/path/path2").unwrap(),
        web_app_auth: WebAppAuth::None,
        tcp_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), DEFAULT_PORT)),
    };
    assert_eq!(expected, options);
}

#[test]
fn test_tcp_url_with_port_parse() {
    let url = "127.0.0.1:1234";

    let options = ConnectionOptions::parse(url, DEFAULT_PORT).unwrap();

    let expected = ConnectionOptions::Tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1234)));
    assert_eq!(expected, options);
}

#[test]
fn test_websocket_url_with_custom_auth() {
    let url = "ws://username:password@192.168.0.1:1234/path/path2,tcp://127.0.0.1";

    let options = ConnectionOptions::parse(url, DEFAULT_PORT).unwrap();

    let expected = ConnectionOptions::WebSocketTunnel {
        websocket_url: Url::parse("ws://192.168.0.1:1234/path/path2").unwrap(),
        web_app_auth: WebAppAuth::Custom {
            username: String::from("username"),
            password: String::from("password"),
        },
        tcp_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), DEFAULT_PORT)),
    };
    assert_eq!(expected, options);
}

#[test]
fn test_websocket_url_without_tcp_addr_parse_must_fail() {
    let url = "ws://192.168.0.1:1234/path";

    let options = ConnectionOptions::parse(url, DEFAULT_PORT);
    assert!(matches!(
        options.err().unwrap(),
        Error::ConnectionUrlParse(ConnectionUrlParseError::IncorrectFormat)
    ));
}
