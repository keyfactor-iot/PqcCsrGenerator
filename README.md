# PQC CSR Generator

A Java command-line tool for generating **PKCS#10 Certificate Signing Requests (CSRs)** using post-quantum cryptographic (PQC) algorithms via [Bouncy Castle](https://www.bouncycastle.org/).

## Overview

This project demonstrates how to use Bouncy Castle to generate key pairs and CSRs for the new NIST post-quantum signature standards, as well as classical algorithms for comparison:

| Algorithm Family | Standard | Description |
|------------------|----------|-------------|
| **ML-DSA** | FIPS 204 | Lattice-based (Module-Lattice Digital Signature Algorithm) |
| **SLH-DSA** | FIPS 205 | Hash-based (Stateless Hash-Based Digital Signature Algorithm) |
| **Falcon** | Pending (FN-DSA) | Lattice-based using NTRU and FFT |
| **Classical** | — | RSA, ECDSA (P-256/P-384), EdDSA (Ed25519/Ed448) |

## Prerequisites

- **Java 25** or later
- **Maven 3.8+**

## Quick Start

```bash
# Clone the repository
git clone https://github.com/keyfactor/pqc-csr-generator.git
cd pqc-csr-generator

# Generate an ML-DSA-87 CSR (highest security level)
mvn compile exec:java -Dexec.args="ML-DSA-87"

# List all supported algorithms
mvn compile exec:java -Dexec.args="--list"
```

## Usage

### Basic Usage

```bash
mvn compile exec:java -Dexec.args="<algorithm>"
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `<algorithm>` | Generate CSR for the specified algorithm |
| `--all` | Generate CSRs for all supported algorithms |
| `--list` | List all supported algorithms |
| `--help` | Show help message |

### Configuration (System Properties)

| Property | Default | Description |
|----------|---------|-------------|
| `-Dcsr.subject` | `CN=Test Certificate,O=Example Org,C=US` | X.500 Subject DN |
| `-Dcsr.outdir` | `.` (current directory) | Output directory for generated files |
| `-Dcsr.san` | *(empty)* | Comma-separated Subject Alternative Names |

### Examples

```bash
# Generate ML-DSA-87 CSR
mvn compile exec:java -Dexec.args="ML-DSA-87"

# Generate all supported algorithms
mvn compile exec:java -Dexec.args="--all"

# Custom subject DN
mvn compile exec:java -Dexec.args="ML-DSA-65" \
    -Dcsr.subject="CN=My Application,O=My Company,C=US"

# With Subject Alternative Names
mvn compile exec:java -Dexec.args="EC-P256" \
    -Dcsr.san="example.com,www.example.com,api.example.com"

# Custom output directory
mvn compile exec:java -Dexec.args="FALCON-512" \
    -Dcsr.outdir="./certs"

# Full example with all options
mvn compile exec:java -Dexec.args="ML-DSA-87" \
    -Dcsr.subject="CN=prod.example.com,O=Example Corp,OU=Engineering,C=US" \
    -Dcsr.san="prod.example.com,www.example.com" \
    -Dcsr.outdir="./output"
```

## Supported Algorithms

### ML-DSA (FIPS 204) — Lattice-Based

| Algorithm | Security Level | Public Key | Signature |
|-----------|----------------|------------|-----------|
| `ML-DSA-44` | ~AES-128 | 1,312 bytes | 2,420 bytes |
| `ML-DSA-65` | ~AES-192 | 1,952 bytes | 3,293 bytes |
| `ML-DSA-87` | ~AES-256 | 2,592 bytes | 4,595 bytes |

### SLH-DSA (FIPS 205) — Hash-Based

Variants use either SHA2 or SHAKE hash functions. The suffix indicates:
- `f` = **fast** signing (larger signatures)
- `s` = **small** signatures (slower signing)

| Algorithm | Hash | Trade-off |
|-----------|------|-----------|
| `SLH-DSA-SHA2-128f` | SHA2-256 | Fast signing |
| `SLH-DSA-SHA2-128s` | SHA2-256 | Small signature |
| `SLH-DSA-SHA2-192f` | SHA2-384 | Fast signing |
| `SLH-DSA-SHA2-192s` | SHA2-384 | Small signature |
| `SLH-DSA-SHA2-256f` | SHA2-512 | Fast signing |
| `SLH-DSA-SHA2-256s` | SHA2-512 | Small signature |
| `SLH-DSA-SHAKE-128f` | SHAKE256 | Fast signing |
| `SLH-DSA-SHAKE-128s` | SHAKE256 | Small signature |
| `SLH-DSA-SHAKE-192f` | SHAKE256 | Fast signing |
| `SLH-DSA-SHAKE-192s` | SHAKE256 | Small signature |
| `SLH-DSA-SHAKE-256f` | SHAKE256 | Fast signing |
| `SLH-DSA-SHAKE-256s` | SHAKE256 | Small signature |

### Falcon (Pending NIST Standardization as FN-DSA)

| Algorithm | Security Level | Public Key | Signature |
|-----------|----------------|------------|-----------|
| `FALCON-512` | ~AES-128 | 897 bytes | ~666 bytes |
| `FALCON-1024` | ~AES-256 | 1,793 bytes | ~1,280 bytes |

### Classical Algorithms (for Comparison)

| Algorithm | Type | Notes |
|-----------|------|-------|
| `Ed25519` | EdDSA | Curve25519, 128-bit security |
| `Ed448` | EdDSA | Curve448, 224-bit security |
| `EC-P256` | ECDSA | NIST P-256 curve |
| `EC-P384` | ECDSA | NIST P-384 curve |
| `RSA-2048` | RSA | SHA256withRSA |
| `RSA-3072` | RSA | SHA256withRSA |
| `RSA-4096` | RSA | SHA256withRSA |

## Output Files

For each algorithm (e.g., `ML-DSA-87`), the tool generates:

| File | Description |
|------|-------------|
| `ml_dsa_87.csr` | PKCS#10 Certificate Signing Request (PEM format) |
| `ml_dsa_87_private.pem` | Private key (PEM format) |

## Verifying Output

### View CSR Contents

```bash
# Using OpenSSL 3.5+ (required for PQC algorithms)
openssl req -in ml_dsa_87.csr -text -noout

# For classical algorithms (any OpenSSL version)
openssl req -in ec_p256.csr -text -noout
```

### Verify CSR Signature

```bash
openssl req -in ml_dsa_87.csr -verify -noout
```

> **Note:** PQC algorithm support requires OpenSSL 3.5 or later. For older OpenSSL versions, only classical algorithms can be inspected.

## Project Structure

```
pqc-csr-generator/
├── pom.xml
├── README.md
└── src/
    └── main/
        └── java/
            └── com/
                └── keyfactor/
                    └── pqc/
                        └── PqcCsrGenerator.java
```

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `bcprov-jdk18on` | 1.83 | Bouncy Castle Provider (core crypto) |
| `bcpkix-jdk18on` | 1.83 | PKCS#10 CSR builder, X.509, CMS |
| `bcutil-jdk18on` | 1.83 | PEM I/O utilities |

## Building

```bash
# Compile
mvn compile

# Package as JAR
mvn package

# Run tests (if any)
mvn test

# Clean build artifacts
mvn clean
```

## Running from JAR

```bash
# Package the application
mvn package

# Run with dependencies on classpath
mvn exec:java -Dexec.args="ML-DSA-87"
```

## Troubleshooting

### "Algorithm not found" Error

Ensure Bouncy Castle providers are registered. The application handles this automatically, but if running in a different context, add:

```java
Security.addProvider(new BouncyCastleProvider());
Security.addProvider(new BouncyCastlePQCProvider());
```

### Java Version Issues

This project requires Java 25. Verify your version:

```bash
java -version
```

If using multiple Java versions, set `JAVA_HOME`:

```bash
export JAVA_HOME=/path/to/jdk-25
mvn compile exec:java -Dexec.args="ML-DSA-87"
```

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 204 - ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 - SLH-DSA Standard](https://csrc.nist.gov/pubs/fips/205/final)
- [Bouncy Castle Java Documentation](https://www.bouncycastle.org/documentation/documentation-java/)
- [Bouncy Castle GitHub](https://github.com/bcgit/bc-java)

## License

Apache 2.0

## Contributing

*Add contribution guidelines here*