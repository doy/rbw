{
  inputs.rust-flake.url = "github:KaiSforza/rust-flake";
  outputs =
    inputs:
    inputs.rust-flake.lib.rust-flakes [
      (inputs.rust-flake.lib.rust-flake {
        root = ./.;
        pkg-overrides = _: _: {
          doCheck = false;
        };
        extra-files = [ ];
      })
    ];
}
