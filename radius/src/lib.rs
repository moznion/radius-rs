#[macro_use]
extern crate log;

pub mod client;
pub mod core;
pub mod server;

#[cfg(all(feature = "md5", feature = "openssl"))]
compile_error!("feature \"md5\" and feature \"openssl\" cannot be enabled at the same time");
