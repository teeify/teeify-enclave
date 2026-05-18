let
  nixpkgs-src = fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/nixos-24.11.tar.gz";
    sha256 = "1s2gr5rcyqvpr58vxdcb095mdhblij9bfzaximrva2243aal3dgx";
  };
  
  rust-overlay-src = fetchTarball {
    url = "https://github.com/oxalica/rust-overlay/archive/592e5dedf04f0eaff1ed0f01ce5db7407d9fc7be.tar.gz";
    sha256 = "014418sbd6ajfpzj7m8cckqy7ky0kcyha5w3fvilbppp8kq46pw5";
  };

  pkgs = import nixpkgs-src {
    overlays =[ (import rust-overlay-src) ];
  };

  enclave-kernel = pkgs.fetchurl {
    url = "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/v1.4.4/blobs/x86_64/bzImage";
    sha256 = "sha256-IQ7adJwTCOtgZxpXnSTbXoo0d8t6JHzzE8KGsJ/i2Fc=";
  };

  rustToolchain = pkgs.rust-bin.stable."1.93.0".default.override {
    targets = [ "x86_64-unknown-linux-gnu" ];
  };

  lib = pkgs.lib;
  
  # 1. THE FIX: Using cleanSource securely ignores .git, and we block all docs/scripts.
  src_files = lib.cleanSourceWith {
    src = lib.cleanSource ./.; 
    filter = path: type:
      let base = baseNameOf path; in
      !(
        base == "target" || 
        base == "result" ||
        base == "teeify-agent.eif" ||
        lib.hasSuffix ".md" base || 
        lib.hasSuffix ".sh" base || 
        lib.hasSuffix ".nix" base
      );
  };

  teeify-bin = (pkgs.makeRustPlatform {
    cargo = rustToolchain;
    rustc = rustToolchain;
  }).buildRustPackage {
    pname = "teeify-enclave";
    version = "1.0.0";
    src = src_files; 
    cargoLock = { lockFile = ./Cargo.lock; };
    cargoBuildFlags =[ "-p" "teeify-enclave" ];
    nativeBuildInputs =[ pkgs.pkg-config pkgs.cmake pkgs.go ];
    buildInputs = [ pkgs.openssl ];
    
    # 2. THE FIX: Use ${src_files} instead of ${./.}
    RUSTFLAGS = "-C target-cpu=x86-64 --remap-path-prefix ${src_files}=/src -C link-arg=-Wl,--build-id=none";
    CARGO_INCREMENTAL = "0";
    
    postInstall = ''
      ${pkgs.binutils}/bin/strip $out/bin/teeify-enclave
    '';
  };

in
{
  image = pkgs.dockerTools.buildImage {
    name = "teeify-enclave-image";
    tag = "latest";
    created = "1970-01-01T00:00:01Z";
    copyToRoot = [ teeify-bin pkgs.cacert ];
    config = {
      Cmd = [ "${teeify-bin}/bin/teeify-enclave" ];
      WorkingDir = "/";
      Env =[
        "AWS_REGION=eu-central-1"
        "TEEIFY_PARENT_VSOCK_CID=3"
        "AWS_EC2_METADATA_DISABLED=true"
        "TEEIFY_KMS_KEY_ID=arn:aws:kms:eu-central-1:668576491768:key/8fc614b5-c335-4611-b2f3-e6ccec4a7ec7"
        "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
      ];
    };
  };
  kernel = enclave-kernel;
}