# The Teeify Trust Protocol

This repository contains the source code for the **Teeify Enclave Engine**. 

### Reproducible Builds
Teeify is built on mathematical proof, not human trust. You can verify the integrity of the platform by reproducing the **PCR0 hash** directly from this source code.

To guarantee bit-for-bit determinism and eliminate hash drift caused by OS timestamps or compiler variations, Teeify utilizes a strict **Nix** build pipeline alongside `libfaketime`. 

#### 1. Requirements
To reproduce the build, we recommend using an Amazon Linux 2023 EC2 instance with the following installed:
-[Nix Package Manager](https://nixos.org/download)
- Docker
- AWS Nitro Enclaves CLI (`aws-nitro-enclaves-cli`)
- Faketime (`libfaketime` / `faketime`)

#### 2. Build Command
We have included the exact deterministic build script used in our production factory. Simply clone this repository and execute the bake script:

```bash
git clone https://github.com/teeify/teeify-enclave.git
cd teeify-enclave
chmod +x bake.sh
./bake.sh
```

*Note: The script utilizes `DOCKER_BUILDKIT`, pins the Rust compiler to `1.85.0` via Nix overlays, and freezes the `.eif` header creation time to guarantee zero entropy.*

#### 3. Current Official Measurement (v1.0.0)
Upon successful completion of the script, the Nitro CLI will output the enclave measurements. Compare the output to our live platform measurement:

**Expected PCR0:** 
`1e7793a5487ae66e02b8114b8d732326c378b4518bf83aca6549802af361d4281bfe54cbb0e48c14c8fe9644cc0dce93`