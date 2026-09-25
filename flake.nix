{
  description = "Unofficial Bitwarden CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; });

      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

      mkRbw =
        {
          lib,
          stdenv,
          rustPlatform,
          openssl,
          pkg-config,
          installShellFiles,
          bash,
          # rbw-fzf
          withFzf ? false,
          fzf,
          perl,
          # rbw-rofi
          withRofi ? false,
          rofi,
          xclip,
          # pass-import
          withPass ? false,
          pass,
        }:
        rustPlatform.buildRustPackage {
          pname = cargoToml.package.name;
          version = cargoToml.package.version;

          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./src
              ./bin
            ];
          };

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = [
            installShellFiles
          ]
          ++ lib.optionals stdenv.hostPlatform.isLinux [ pkg-config ];

          buildInputs = [ bash ]; # for git-credential-rbw

          preConfigure = lib.optionalString stdenv.hostPlatform.isLinux ''
            export OPENSSL_INCLUDE_DIR="${openssl.dev}/include"
            export OPENSSL_LIB_DIR="${lib.getLib openssl}/lib"
          '';

          postInstall = ''
            install -Dm755 -t $out/bin bin/git-credential-rbw
          ''
          + lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
            installShellCompletion --cmd rbw \
              --bash <($out/bin/rbw gen-completions bash) \
              --fish <($out/bin/rbw gen-completions fish) \
              --nushell <($out/bin/rbw gen-completions nushell) \
              --zsh <($out/bin/rbw gen-completions zsh)
          ''
          + lib.optionalString withFzf ''
            install -Dm755 -t $out/bin bin/rbw-fzf
            substituteInPlace $out/bin/rbw-fzf \
              --replace-fail fzf ${fzf}/bin/fzf \
              --replace-fail perl ${perl}/bin/perl
          ''
          + lib.optionalString withRofi ''
            install -Dm755 -t $out/bin bin/rbw-rofi
            substituteInPlace $out/bin/rbw-rofi \
              --replace-fail rofi ${rofi}/bin/rofi \
              --replace-fail xclip ${xclip}/bin/xclip
          ''
          + lib.optionalString withPass ''
            install -Dm755 -t $out/bin bin/pass-import
            substituteInPlace $out/bin/pass-import \
              --replace-fail pass ${pass}/bin/pass
          '';

          meta = {
            description = "Unofficial command line client for Bitwarden";
            homepage = "https://crates.io/crates/rbw";
            license = lib.licenses.mit;
            mainProgram = "rbw";
          };
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor.${system};
          rbw = pkgs.callPackage mkRbw { };
        in
        {
          inherit rbw;
          default = rbw;
        }
      );

      overlays.default = final: _prev: {
        rbw = final.callPackage mkRbw { };
      };

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor.${system};
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.default ];
            packages = with pkgs; [
              cargo
              rustc
              rustfmt
              clippy
              rust-analyzer
            ];
          };
        }
      );
    };
}
