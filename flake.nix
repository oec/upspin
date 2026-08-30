{
  description = "Upspin — fork by Özgür Kesim";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs = { self, nixpkgs }:
    let
      allSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs allSystems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });
    in
    {
      # ---- Expose as a buildable package: `nix build .#upspin` ----
      packages = forAllSystems ({ pkgs }: {
        default = self.packages.${pkgs.system}.upspin;

        upspin = pkgs.buildGoModule {
          pname = "upspin";
          version = "trustanchor-experiment-2026-08-30";  # or a real tag from your repo

          # Build from the local source tree in this repo
          src = ./.;

          # Set to lib.fakeHash first, then replace with the real value
          # from the build error output
          vendorHash = sha256-YemCe8OrPdx4y7308ZlYmqqT7QdXrGz7WUX9BOkzBS8=;

          doCheck = false;

          meta = {
            description = "Global name space for storing data akin to a filesystem";
            homepage = "https://upspin.io";
            license = pkgs.lib.licenses.bsd3;
            platforms = pkgs.lib.platforms.linux ++ pkgs.lib.platforms.darwin;
          };
        };
      });

      # ---- Expose an overlay so NixOS can override pkgs.upspin ----
      overlays = {
        default = final: prev: {
          upspin = self.packages.${final.system}.upspin;
        };
      };
    };
}

