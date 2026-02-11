# PQC CSR Generator

A Java command-line tool for generating **PKCS#10 Certificate Signing Requests (CSRs)** using post-quantum cryptographic (PQC) algorithms via [Bouncy Castle](https://www.bouncycastle.org/).

## Overview

This project demonstrates how to use Bouncy Castle to generate key pairs and CSRs for the new NIST post-quantum signature standards (FIPS 204, FIPS 205), as well as classical algorithms for comparison.

| Algorithm Family | Standard | Description |
|------------------|----------|-------------|
| **ML-DSA** | FIPS 204 | Lattice-based (Module-Lattice Digital Signature Algorithm) |
| **SLH-DSA** | FIPS 205 | Hash-based (Stateless Hash-Based Digital Signature Algorithm) |
| **Classical** | — | RSA, ECDSA (P-256/P-384), EdDSA (Ed25519/Ed448) |

---

## 🐋 Running with Docker (Recommended)

Using Docker allows you to run the generator without manually installing JDK 24 or Maven on your host machine.

### 1. Setup
First, ensure you have the required Docker configuration files. You can download them directly from the repository:

```bash
# Download Dockerfile
curl -O https://raw.githubusercontent.com/keyfactor-iot/PqcCsrGenerator/main/Dockerfile

# Download docker-compose.yaml
curl -O https://raw.githubusercontent.com/keyfactor-iot/PqcCsrGenerator/main/docker-compose.yaml
```

Next, ensure you have an `out` directory created in your project root to receive the generated files:
```bash
mkdir out
```

### 2. Build and Run
The simplest way to run the tool is using Docker Compose. This method ensures that file permissions are handled correctly on Linux (Ubuntu) while maintaining the flexibility to customize your CSR.

#### **Initialize Environment**
Before running the container, set your local user and group IDs. This handles the `readonly` variable restriction on Linux and ensures that the generated files in the `out/` folder are owned by you rather than `root`.

```bash
# Create the environment file (Run this once)
echo "CURRENT_UID=$(id -u)" > .env
echo "CURRENT_GID=$(id -g)" >> .env
```

#### **Execution**
Build the container and run the generator. By default, this will generate a CSR using the **ML-DSA-65** algorithm.

```bash
# Works on Mac, Windows, and Linux
docker compose up --build
```
---

### 3. Customizing the Execution
You can override the algorithm, the Certificate Subject DN, or **Subject Alternative Names (SAN)** by modifying the `command` or `environment` sections in `docker-compose.yaml`.

The tool automatically detects if a SAN is a DNS name or an IP address and encodes it correctly in the X.509 extension.

**To change the Subject DN, SAN (DNS & IP), or Algorithm on the fly:**
```bash
# Example: Custom Subject with both DNS and IP Address SANs
docker compose run --rm \
  -e JAVA_OPTS="-Dcsr.subject='CN=PQC-Server,O=Keyfactor,C=US' -Dcsr.san='pqc.local,192.168.1.100' -Dcsr.outdir=/output" \
  pqc-gen "ML-DSA-65"
```

### Troubleshooting
* **"readonly variable" error:** If you see `UID: readonly variable`, ensure you are using the `CURRENT_UID` approach in the `.env` file rather than trying to assign to the protected shell variable `UID`.
* **Help menu appears instead of generating CSR:** Java is strict about argument order. Ensure system properties (`-D`) are in the `JAVA_OPTS` and the algorithm name (e.g., `ML-DSA-65`) is the last argument.

### Troubleshooting Docker
* **Empty `out` directory:** Ensure you are running the docker command from the same folder that contains the `docker-compose.yaml` and `out` directory.
* **"Permission Denied" (Linux):** If files in `out` are locked by root, run: `sudo chown -R $USER:$USER out/` and then use the `UID/GID` command above for future runs.

---

## 🛠 Manual Building (Local Java 24)

### Prerequisites
- **Java 24** (Required for the latest PQC features)
- **Maven 3.8+**

### Compile and Package
Because this project requires Bouncy Castle dependencies, you must build the "Fat JAR":
```bash
mvn clean package
```

### Run from JAR
```bash
java -jar target/PqcCsrGenerator.jar "ML-DSA-65"
```

---

## Configuration Reference

### System Properties
| Property | Default | Description |
|----------|---------|-------------|
| `-Dcsr.subject` | `CN=Test Certificate,O=Example Org,C=US` | X.500 Subject DN |
| `-Dcsr.outdir` | `/output` (Docker) or `.` | Output directory for keys and CSRs |

### Output Files
For an algorithm like `ML-DSA-65`, the tool generates:
- `ml_dsa_65.csr`: The PEM-encoded Certificate Signing Request.
- `ml_dsa_65_private.pem`: The PEM-encoded Private Key.

---

## Supported Algorithms

### ML-DSA (FIPS 204)
- `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`

### SLH-DSA (FIPS 205)
- `SLH-DSA-SHA2-128f`, `SLH-DSA-SHA2-128s`
- `SLH-DSA-SHAKE-128f`, `SLH-DSA-SHAKE-128s`
- *(And 192/256 variants)*

### Falcon (Pending)
- `FALCON-512`, `FALCON-1024`

---

## Troubleshooting Manual Builds

**"No main manifest attribute"**
This happens if you try to run the "thin" jar. Always use the jar produced by the `maven-assembly-plugin` (located in `target/PqcCsrGenerator.jar`).

**"UnsupportedClassVersionError"**
Ensure your local `java -version` is 24. If using Docker, this is handled automatically.

---

## License
Apache 2.0