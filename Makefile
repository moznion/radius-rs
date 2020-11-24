build:
	cargo build

gen:
	cat /dev/null > $(PWD)/src/rfc2865.rs
	cargo run --bin code_gen $(PWD)/dicts/dictionary.rfc2865 $(PWD)/src/rfc2865.rs
	cargo fmt
