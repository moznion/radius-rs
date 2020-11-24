gen:
	cargo run --bin code_gen $(PWD)/dicts/dictionary.rfc2865 $(PWD)/src/rfc2865.rs
	cargo fmt
