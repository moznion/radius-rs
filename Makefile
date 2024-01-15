check_all: check check_openssl check_md5
check: test lint
check_openssl: lint_with_openssl build_with_openssl test_with_openssl
check_md5: lint_with_md5 build_with_md5 test_with_md5

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

build_with_openssl:
	cd radius && cargo build --verbose --no-default-features --features openssl

test_with_openssl:
	cd radius && cargo test --verbose --no-default-features --features openssl

lint_with_openssl:
	cd radius && cargo clippy --verbose --no-default-features --features openssl

build_with_md5:
	cd radius && cargo build --verbose --no-default-features --features md5

test_with_md5:
	cd radius && cargo test --verbose --no-default-features --features md5

lint_with_md5:
	cd radius && cargo clippy --verbose --no-default-features --features md5

