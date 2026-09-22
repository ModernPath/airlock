# Nix packaging. The cargo workflow is unchanged; this is only for installing
# airlock with Nix.
#
#   nix build                    -> ./result/bin/airlock
#   nix run . -- --help
#   nix develop                  # cargo, rustc, clippy, rustfmt, rust-analyzer
#   nix flake check
#   nix profile install github:ModernPath/airlock
{
  description = "Credential broker for AI agents — tools get your secrets, the agent never does";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      # x86_64-darwin is kept for consumers following a nixpkgs that still has
      # it; it does not evaluate against the unstable pin above, since nixpkgs
      # 26.11 dropped that platform.
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      mkAirlock =
        pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "airlock";
          version = (nixpkgs.lib.importTOML ./Cargo.toml).package.version;

          src = self;

          cargoLock.lockFile = ./Cargo.lock;

          # build.rs shells out to git, which this build cannot do: no git in
          # the sandbox, and `src` is a store copy with no .git. Hand it the
          # revision the flake was evaluated from instead. `shortRev` exists
          # only for a clean checkout; a dirty tree gives `dirtyShortRev`,
          # which carries a "-dirty" suffix that GIT_DIRTY already conveys.
          AIRLOCK_GIT_HASH = nixpkgs.lib.removeSuffix "-dirty" (
            self.shortRev or self.dirtyShortRev or "unknown"
          );
          AIRLOCK_GIT_DIRTY = if self ? dirtyRev then "true" else "false";

          # Only the unit tests: the suites under tests/ start a daemon and nest
          # an OS sandbox inside the Nix build sandbox, which is unavailable there.
          cargoTestFlags = [ "--lib" ];

          meta = {
            description = "Credential broker for AI agents — tools get your secrets, the agent never does";
            homepage = "https://github.com/ModernPath/airlock";
            license = pkgs.lib.licenses.mit;
            mainProgram = "airlock";
            platforms = pkgs.lib.platforms.darwin ++ pkgs.lib.platforms.linux;
          };
        };
    in
    {
      packages = forAllSystems (pkgs: rec {
        airlock = mkAirlock pkgs;
        default = airlock;
      });

      # For consumers: nixpkgs.overlays = [ inputs.airlock.overlays.default ];
      overlays.default = final: _prev: {
        airlock = mkAirlock final;
      };

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.rust-analyzer
          ];
          # rust-analyzer cannot find the std sources without this when rustc
          # comes from nixpkgs rather than rustup.
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-tree);
    };
}
