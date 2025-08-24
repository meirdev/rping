.PHONY: fmt

fmt:
	cargo +nightly fmt

release:
	cargo build --release
