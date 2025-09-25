{
  description = "rbw release build";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = pkgs.lib;

        defaultBinaryRenames = {
          rbw = "rbw";
          "rbw-agent" = "rbw-agent";
        };

        mkRbw = { withFzf ? false, withRofi ? false, withPass ? false, binaryRenames ? defaultBinaryRenames }:
          let
            renamePairs = lib.filterAttrs (from: to: from != to) binaryRenames;
            renameScript = lib.concatStringsSep "\n" (lib.mapAttrsToList (from: to: ''
              if [ -e "$out/bin/${from}" ]; then
                mv "$out/bin/${from}" "$out/bin/${to}"
              fi
            '') renamePairs);
            mainBinary = lib.attrByPath [ "rbw" ] "rbw" binaryRenames;
          in pkgs.rustPlatform.buildRustPackage rec {
            pname = "rbw-dev";
            version = "1.14.1-dev";

            src = lib.cleanSourceWith {
              src = ./.;
              filter = lib.cleanSourceFilter;
            };

            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs =
              [ pkgs.installShellFiles ]
              ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.pkg-config ];

            buildInputs =
              [ pkgs.bash ]
              ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.openssl ]
              ++ lib.optionals withFzf [ pkgs.fzf pkgs.perl ]
              ++ lib.optionals withRofi [ pkgs.rofi pkgs.xclip ]
              ++ lib.optionals withPass [ pkgs.pass ];

            cargoBuildFlags = [ "--locked" ];
            cargoInstallFlags = [ "--locked" ];

            doCheck = false;

            preConfigure = lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
              export OPENSSL_INCLUDE_DIR="${pkgs.openssl.dev}/include"
              export OPENSSL_LIB_DIR="${lib.getLib pkgs.openssl}/lib"
            '';

            postInstall = ''
              install -Dm755 -t $out/bin bin/git-credential-rbw
            ''
            + lib.optionalString (renameScript != "") ''
              ${renameScript}
            ''
            + lib.optionalString (pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform) ''
              installShellCompletion --cmd ${mainBinary} \
                --bash <($out/bin/${mainBinary} gen-completions bash) \
                --fish <($out/bin/${mainBinary} gen-completions fish) \
                --zsh <($out/bin/${mainBinary} gen-completions zsh)
            ''
            + lib.optionalString withFzf ''
              install -Dm755 -t $out/bin bin/rbw-fzf
              substituteInPlace $out/bin/rbw-fzf \
                --replace fzf ${pkgs.fzf}/bin/fzf \
                --replace perl ${pkgs.perl}/bin/perl
            ''
            + lib.optionalString withRofi ''
              install -Dm755 -t $out/bin bin/rbw-rofi
              substituteInPlace $out/bin/rbw-rofi \
                --replace rofi ${pkgs.rofi}/bin/rofi \
                --replace xclip ${pkgs.xclip}/bin/xclip
            ''
            + lib.optionalString withPass ''
              install -Dm755 -t $out/bin bin/pass-import
              substituteInPlace $out/bin/pass-import \
                --replace pass ${pkgs.pass}/bin/pass
            '';

            meta = with lib; {
              description = "Unofficial Bitwarden CLI";
              homepage = "https://git.tozt.net/rbw";
              changelog = "https://git.tozt.net/rbw/plain/CHANGELOG.md?id=${version}";
              license = licenses.mit;
              maintainers = [];
              mainProgram = mainBinary;
            };
          };

        rbw = mkRbw { };
        rbw-dev = mkRbw { rbw = "rbw-dev"; rbw-agent = "rbw-agent-dev"; };
        defaultMainBinary = lib.attrByPath [ "rbw" ] "rbw" defaultBinaryRenames;
      in {
        packages = {
          inherit rbw;
          default = rbw;
          rbw-with-fzf = mkRbw { withFzf = true; };
          rbw-with-rofi = mkRbw { withRofi = true; };
          rbw-with-pass = mkRbw { withPass = true; };
        };

        apps.default = {
          type = "app";
          program = "${rbw}/bin/${defaultMainBinary}";
        };

        checks.default = rbw;

        devShells.default = pkgs.mkShell {
          inputsFrom = [ rbw ];
          nativeBuildInputs = with pkgs; [
            cargo
            clippy
            rustfmt
          ] ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.pkg-config pkgs.openssl ];
        };
      }
    );
}
