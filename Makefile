check: test lint

test:
	cargo test

build:
	cargo build

lint:
	cargo clippy

gen:
	bash ./scripts/generate-code.sh
	$(MAKE) fix

fix:
	cargo fix --allow-dirty --allow-staged
	cargo fmt

