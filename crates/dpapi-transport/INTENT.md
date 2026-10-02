The `dpapi-transport` crate implements a set of traits and exports a set of types for implementing custom DPAPI RPC communication transport.
Different environments and platforms have different limitations and we cannot rely on system `TcpStream` and `WebSocket`.
