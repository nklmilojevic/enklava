{
  description = "Secure Enclave SSH keys and Git signing for macOS, with a Home Manager module";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    # Only used by the module check; consumers can point it at their own.
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ self, flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
      ];

      perSystem =
        { pkgs, self', ... }:
        {
          packages.default = pkgs.callPackage ./package.nix { };

          checks = {
            cli = pkgs.callPackage ./tests/cli.nix { enklava = self'.packages.default; };
            module = pkgs.callPackage ./tests/module.nix {
              inherit self;
              inherit (inputs) home-manager;
            };
            gofmt = pkgs.runCommand "enklava-gofmt" { nativeBuildInputs = [ pkgs.go ]; } ''
              unformatted=$(gofmt -l ${./cmd} ${./internal})
              [ -z "$unformatted" ] || { echo "not gofmt-formatted: $unformatted"; exit 1; }
              touch $out
            '';
          };

          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              go
              gopls
              goreleaser
            ];
          };

          formatter = pkgs.nixfmt;
        };

      flake = {
        overlays.default = final: _prev: {
          enklava = final.callPackage ./package.nix { };
        };

        homeManagerModules.default = import ./module.nix { inherit self; };
      };
    };
}
