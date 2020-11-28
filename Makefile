test:
	cargo test

build:
	cargo build

lint:
	cargo clippy

gen:
	bash ./scripts/generate_code.sh
