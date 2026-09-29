The `dpapi-native-transport` implements traits from the `dpapi-transport` crate using system native TCP and WebSockets stack.
This implementation is suitable for all platforms that supports `tokio::net::TcpStream`.
