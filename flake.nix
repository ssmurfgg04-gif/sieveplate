{
    description = "sieveplate — a living cell-grid runtime";

    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
        flake-utils.url = "github:numtide/flake-utils";
    };

    outputs = { self, nixpkgs, flake-utils }:
        flake-utils.lib.eachDefaultSystem (system:
            let
                pkgs = nixpkgs.legacyPackages.${system};
            in
            {
                packages.default = pkgs.rustPlatform.buildRustPackage {
                    pname = "sieveplate";
                    version = "0.1.0";
                    src = ./.;

                    cargoLock = {
                        lockFile = ./Cargo.lock;
                    };

                    doCheck = true;

                    meta = with pkgs.lib; {
                        description =
                            "A living cell-grid runtime: sleeping transactional cells, capability-gated channels, content-addressed memory, declarative system closures";
                        homepage = "https://github.com/ssmurfgg04-gif/sieveplate";
                        license = licenses.asl20;
                        mainProgram = "sieve";
                        platforms = platforms.linux;
                    };
                };

                devShells.default = pkgs.mkShell {
                    buildInputs = with pkgs; [
                        rustc
                        cargo
                        rustfmt
                        clippy
                        rust-analyzer
                    ];
                    RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
                };
            });
}
