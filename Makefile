NAME = $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].name')
VERSION = $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')

DEB_PACKAGE = $(NAME)_$(VERSION)_amd64.deb
TGZ_PACKAGE = $(NAME)_$(VERSION)_linux_amd64.tar.gz

all: build
.PHONY: all

build:
	@cargo build --all-targets --target x86_64-unknown-linux-musl
.PHONY: build

release:
	@cargo build --release --all-targets --target x86_64-unknown-linux-musl
.PHONY: release

test:
	@RUST_BACKTRACE=1 cargo test --target x86_64-unknown-linux-musl
.PHONY: test

check:
	@cargo check --all-targets --target x86_64-unknown-linux-musl
.PHONY: check

doc:
	@cargo doc --workspace
.PHONY: doc

clean:
	@rm -rf *.log pkg
.PHONY: clean

cleanall: clean
	@cargo clean
.PHONY: cleanall

completion: release
	@mkdir -p target/x86_64-unknown-linux-musl/release/completion
	@./target/x86_64-unknown-linux-musl/release/rbw gen-completions bash > target/x86_64-unknown-linux-musl/release/completion/bash
	@./target/x86_64-unknown-linux-musl/release/rbw gen-completions zsh > target/x86_64-unknown-linux-musl/release/completion/zsh
	@./target/x86_64-unknown-linux-musl/release/rbw gen-completions fish > target/x86_64-unknown-linux-musl/release/completion/fish
.PHONY: completion

package: pkg/$(DEB_PACKAGE) pkg/$(TGZ_PACKAGE)
.PHONY: package

pkg:
	@mkdir pkg

pkg/$(DEB_PACKAGE): release completion | pkg
	@cargo deb --no-build --target x86_64-unknown-linux-musl && mv target/x86_64-unknown-linux-musl/debian/$(DEB_PACKAGE) pkg
