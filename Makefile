all: check build test

export RUSTFLAGS=-Dwarnings

test:
	cargo test

build:
	cargo build --target wasm32-unknown-unknown --release
	CARGO_TARGET_DIR=target-tiny cargo +nightly build --target wasm32-unknown-unknown --release \
		-Z build-std=std,panic_abort \
		-Z build-std-features=panic_immediate_abort
	cd target/wasm32-unknown-unknown/release/ && \
		for i in *.wasm ; do \
			wasm-opt -Oz "$$i" -o "$$i.tmp" && mv "$$i.tmp" "$$i"; \
			ls -l "$$i"; \
		done
	cd target-tiny/wasm32-unknown-unknown/release/ && \
		for i in *.wasm ; do \
			wasm-opt -Oz "$$i" -o "$$i.tmp" && mv "$$i.tmp" "$$i"; \
			ls -l "$$i"; \
		done

check:
	cargo hack --feature-powerset check --all-targets
	cargo check --release --target wasm32-unknown-unknown

watch:
	cargo watch --clear --watch-when-idle --shell '$(MAKE)'

fmt:
	cargo fmt --all

clean:
	cargo clean
	CARGO_TARGET_DIR=target-tiny cargo +nightly clean

# Build all projects as if they are being published to crates.io, and do so for
# all feature and target combinations.
publish-dry-run:
	cargo +stable hack --feature-powerset publish --locked --dry-run --exclude-features testutils --target wasm32-unknown-unknown --package soroban-token-contract
	cargo +stable hack --feature-powerset publish --locked --dry-run --package soroban-token-contract

# Publish publishes the crate to crates.io. The dry-run is a dependency because
# the dry-run target will verify all feature set combinations.
publish: publish-dry-run
	cargo +stable publish --locked --package soroban-token-contract --target wasm32-unknown-unknown
