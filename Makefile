.PHONY: fmt

fmt:
	cargo +nightly fmt

release:
	cargo build --release

release-musl:
	rustup target add x86_64-unknown-linux-musl
	cargo build --release --target x86_64-unknown-linux-musl
