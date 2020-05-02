NAME = $(shell cargo metadata --no-deps --format-version 1 | jq '.packages[0].name')
VERSION = $(shell cargo metadata --no-deps --format-version 1 | jq '.packages[0].version')

DEB_PACKAGE = $(NAME)_$(VERSION)_amd64.deb

all:
	@cargo build
.PHONY: all

release:
	@cargo build --release
.PHONY: release

test:
	@RUST_BACKTRACE=1 cargo test
.PHONY: test

check:
	@cargo check --all-targets
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

package: pkg/$(DEB_PACKAGE)
.PHONY: package

pkg:
	@mkdir pkg

pkg/$(DEB_PACKAGE): | pkg
	@cargo deb && mv target/debian/$(DEB_PACKAGE) pkg

pkg/$(DEB_PACKAGE).minisig: pkg/$(DEB_PACKAGE)
	@minisign -Sm pkg/$(DEB_PACKAGE)

release-dir-deb:
	@ssh tozt.net mkdir -p releases/teleterm/deb
.PHONY: release-dir-deb

publish: publish-crates-io publish-git-tags publish-deb
.PHONY: publish

publish-crates-io: test
	@cargo publish
.PHONY: publish-crates-io

# force shell instead of exec to work around
# https://savannah.gnu.org/bugs/?57962 since i have ~/.bin/git as a directory
publish-git-tags: test
	@:; git tag $(VERSION)
	@:; git push --tags
.PHONY: publish-git-tags

publish-deb: test pkg/$(DEB_PACKAGE) pkg/$(DEB_PACKAGE).minisig release-dir-deb
	@scp pkg/$(DEB_PACKAGE) pkg/$(DEB_PACKAGE).minisig tozt.net:releases/rbw/deb
.PHONY: publish-deb
