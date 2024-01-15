# radius-rs [![Check](https://github.com/moznion/radius-rs/workflows/Check/badge.svg)](https://github.com/moznion/radius-rs/actions) [![crates.io](https://img.shields.io/crates/v/radius.svg)](https://crates.io/crates/radius)

An async/await native implementation of the RADIUS server and client for Rust. And this also can be used for parsing/constructing (i.e. decoding/encoding) purposes as a RADIUS library.

## Description

This RADIUS server and client implementation use [tokio](https://tokio.rs/) to support asynchronous operations natively. This implementation satisfies basic functions that are described in [RFC2865](https://tools.ietf.org/html/rfc2865).

## Usage

Simple example implementations are here:

- [server](./examples/server.rs)
- [client](./examples/client.rs)

Those examples implement a quite simple `Access-Request` processor. You can try those with the following commands.

```
$ RUST_LOG=debug cargo run --example server
$ RUST_LOG=debug cargo run --example client # in another shell
```

## Supported Dictionaries

This supports the following RFC dictionaries at the moment:

- [RFC2865](https://tools.ietf.org/html/rfc2865)
- [RFC2866](https://tools.ietf.org/html/rfc2866)
- [RFC2867](https://tools.ietf.org/html/rfc2867)
- [RFC2868](https://tools.ietf.org/html/rfc2868)
- [RFC2869](https://tools.ietf.org/html/rfc2869)
- [RFC3162](https://tools.ietf.org/html/rfc3162)
- [RFC3576](https://tools.ietf.org/html/rfc3576)
- [RFC3580](https://tools.ietf.org/html/rfc3580)
- [RFC4072](https://tools.ietf.org/html/rfc4072)
- [RFC4372](https://tools.ietf.org/html/rfc4372)
- [RFC4603](https://tools.ietf.org/html/rfc4603)
- [RFC4675](https://tools.ietf.org/html/rfc4675)
- [RFC4818](https://tools.ietf.org/html/rfc4818)
- [RFC4849](https://tools.ietf.org/html/rfc4849)
- [RFC5090](https://tools.ietf.org/html/rfc5090)
- [RFC5176](https://tools.ietf.org/html/rfc5176)
- [RFC5607](https://tools.ietf.org/html/rfc5607)
- [RFC5904](https://tools.ietf.org/html/rfc5904)
- [RFC6519](https://tools.ietf.org/html/rfc6519)
- [RFC6572](https://tools.ietf.org/html/rfc6572)
- [RFC6677](https://tools.ietf.org/html/rfc6677)
- [RFC6911](https://tools.ietf.org/html/rfc6911)
- [RFC7055](https://tools.ietf.org/html/rfc7055)
- [RFC7155](https://tools.ietf.org/html/rfc7155)

## Cryptography method feature option

By default, this library uses MD5 for authentication.
Starting from version v0.4.0, it also supports [OpenSSL](https://www.openssl.org/).

If you prefer to use OpenSSL, please add the following lines to your Cargo.toml:

```toml
[dependencies]
radius = { version = "__version__", default-features = false, features = ["openssl"] }
```

## Implementation guide for your RADIUS application

### Common

- `Packet` struct represents request packet and response one.
  - This struct has a list of AVPs.
  - You can get a specific AVP by RFC dictionary module.
    - e.g. `rfc2865::lookup_user_name(packet)`
      - This method returns `Some(Result<String, AVPError>)` if the packet contains `User-Name` attribute.
      - On the other hand, if the package doesn't have that attribute, it returns `None`.
  - You can construct a packet with RFC dictionary module.
    - e.g. `rfc2865::add_user_name(&mut packet, "user")`
      - This method adds a `User-Name` AVP to the packet.
  - Please refer to the rustdoc for each RFC dictionary module in detail.

### Server

- Must implement `RequestHandler<T, E>` interface.
  - This interface method is the core function of the server application what you need.
- Please refer also to the example implementation: [server](./examples/server.rs)

### Client

- Please refer also to the example implementation: [client](./examples/client.rs)

## Roadmap

- Support the following RFC dictionaries:
  - rfc4679
  - rfc5447
  - rfc5580
  - rfc6929
  - rfc6930
  - rfc7268
  - rfc7499
  - rfc7930
  - rfc8045
  - rfc8559

## Development guide for this library

### How to generate code from dictionary

```shell
$ make gen
```

`code-generator` sub project has the responsibility to generate the Rust code according to
given RFC dictionary files. The dictionary files are in `dicts` directory.

The format of the dictionary files respect the [FreeRADIUS project's ones](https://github.com/FreeRADIUS/freeradius-server/tree/master/share/dictionary/radius).

## Note

The original implementation and design of this are inspired by [layeh/radius](https://github.com/layeh/radius).

## Author

moznion (<moznion@gmail.com>)
