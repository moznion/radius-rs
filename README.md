# radius-rs

A async/await native implementation of the RADIUS server and client for Rust.

## Description

**THIS PROJECT IS UNDER DEVELOPMENT STATUS. IT WOULD CHANGE WITHOUT NOTICES.**

This RADIUS server and client implementation use [tokio](https://tokio.rs/) to support asynchronous operations natively. This implementation satisfies basic functions that are described in [RFC2865](https://tools.ietf.org/html/rfc2865).

This supports the following RFC dictionaries at the moment:

- [RFC2865](https://tools.ietf.org/html/rfc2865)
- [RFC2866](https://tools.ietf.org/html/rfc2866)
- [RFC2867](https://tools.ietf.org/html/rfc2867)

## Usage

Simple example implementations are here:

- [server](./examples/server.rs)
- [client](./examples/client.rs)

## Roadmap

- timeout feature on the client
- retransmission feature on the client
- Support the following RFC dictionaries:
  - rfc2868
  - rfc2869
  - rfc3162
  - rfc3576
  - rfc3580
  - rfc4072
  - rfc4372
  - rfc4603
  - rfc4675
  - rfc4679
  - rfc4818
  - rfc4849
  - rfc5090
  - rfc5176
  - rfc5447
  - rfc5580
  - rfc5607
  - rfc5904
  - rfc6519
  - rfc6572
  - rfc6677
  - rfc6911
  - rfc6929
  - rfc6930
  - rfc7055
  - rfc7155
  - rfc7268
  - rfc7499
  - rfc7930
  - rfc8045
  - rfc8559

## Note

Original implementation and design of this are based on [layeh/radius](https://github.com/layeh/radius).

## Author

moznion (<moznion@gmail.com>)

