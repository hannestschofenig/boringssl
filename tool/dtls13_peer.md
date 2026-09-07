# DTLS 1.3 Interoperability Peer

`dtls13_peer` is a small UDP client/server example for BoringSSL's DTLS 1.3
implementation. It is intended for interoperability and fault-injection tests,
not as a production server.

The peer:

- uses `DTLS_method()` with minimum and maximum version set to DTLS 1.3;
- drives `DTLSv1_get_timeout()` and `DTLSv1_handle_timeout()`;
- supports an optional group list and client-side certificate verification;
- exchanges a short application datagram after the handshake;
- prints stable `HANDSHAKE_OK` and `APPLICATION_DATA_OK` markers.

## Build

```sh
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target dtls13_peer
```

## Run

Start a server:

```sh
./build/dtls13_peer --server --host 127.0.0.1 --port 4444 \
  --cert /path/to/server-cert.pem --key /path/to/server-key.pem
```

Connect a client and verify the server certificate:

```sh
./build/dtls13_peer --client --host 127.0.0.1 --port 4444 \
  --ca /path/to/ca-cert.pem
```

Use `--curves P-256` or `--curves X25519MLKEM768` to constrain the offered
group. Run the executable without arguments to print all supported options.

The standard `bssl client` and `bssl server` programs use TCP and
`TLS_method()`, so they cannot replace this peer in UDP/DTLS tests.
