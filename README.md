# 🔒 Teeify Enclave Engine

This repository contains the source code for the **Teeify Enclave Engine**. 

Teeify is the orchestration layer for the autonomous economy. This specific repository holds the Rust-based Secure Compute Engine, which embeds a JavaScript runtime (`boa_engine`), a TLS-passthrough proxy, and AWS KMS integration directly into a hardware-isolated AWS Nitro Enclave.

---

## 🛡️ The Teeify Trust Protocol (Reproducible Builds)

Teeify is built on mathematical proof, not human trust. You can verify the integrity of the platform by reproducing the **PCR0 hash** directly from this source code.

To guarantee bit-for-bit determinism and eliminate hash drift caused by OS timestamps or compiler variations, Teeify utilizes a strict **Nix** build pipeline alongside `libfaketime`. 

### 1. Requirements
To reproduce the build, we recommend using an Amazon Linux 2023 EC2 instance with the following installed:
- [Nix Package Manager](https://nixos.org/download)
- Docker
- AWS Nitro Enclaves CLI (`aws-nitro-enclaves-cli`)
- Faketime (`libfaketime` / `faketime`)

### 2. Build Command
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
`420a1a2d278c44ec825f6976439b4092a71f6e21ae18615ce0eca32d68146adc08e0eeeba1729eff5fc6ead480e65a76`