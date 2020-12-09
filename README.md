# radius-rs

A async/await native implementation of the RADIUS server and client for Rust.

## Description

This RADIUS server and client implementation use [tokio](https://tokio.rs/) to support asynchronous operations natively. This implementation satisfies basic functions that are described in [RFC2865](https://tools.ietf.org/html/rfc2865).

## Usage

Simple example implementations are here:

- [server](./examples/server.rs)
- [client](./examples/client.rs)

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

## Note

The original implementation and design of this are inspired by [layeh/radius](https://github.com/layeh/radius).

## Author

moznion (<moznion@gmail.com>)
