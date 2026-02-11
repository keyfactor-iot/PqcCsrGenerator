package com.keyfactor.pqc;

/*
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  PQC CSR GENERATOR                                              │
 * │  Generates key pairs and PKCS#10 CSRs using Bouncy Castle       │
 * ├─────────────────────────────────────────────────────────────────┤
 * │  QUICK START                                                    │
 * ├─────────────────────────────────────────────────────────────────┤
 * │  mvn compile exec:java -Dexec.args="ML-DSA-87"                  │
 * │  mvn compile exec:java -Dexec.args="--all"                      │
 * │  mvn compile exec:java -Dexec.args="--list"                     │
 * ├─────────────────────────────────────────────────────────────────┤
 * │  CONFIGURATION (via system properties)                          │
 * ├─────────────────────────────────────────────────────────────────┤
 * │  -Dcsr.subject="CN=My Cert,O=My Org,C=US"                       │
 * │  -Dcsr.outdir="/path/to/output"                                 │
 * │  -Dcsr.san="example.com,www.example.com"  (optional SANs)       │
 * ├─────────────────────────────────────────────────────────────────┤
 * │  VERIFY OUTPUT                                                  │
 * ├─────────────────────────────────────────────────────────────────┤
 * │  openssl req -in ml_dsa_87.csr -text -noout                     │
 * │  (Requires OpenSSL 3.5+ for PQC algorithm support)              │
 * └─────────────────────────────────────────────────────────────────┘
 */

import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

/**
 * Generates key pairs and PKCS#10 CSRs for post-quantum and classical algorithms.
 *
 * <p>Supported algorithm families:</p>
 * <ul>
 *   <li><b>ML-DSA</b> (FIPS 204) — Lattice-based, NIST standard</li>
 *   <li><b>SLH-DSA</b> (FIPS 205) — Hash-based, NIST standard</li>
 *   <li><b>Falcon</b> — Lattice-based (NTRU), pending NIST standardization as FN-DSA</li>
 *   <li><b>Classical</b> — RSA, ECDSA, EdDSA for comparison</li>
 * </ul>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * // Generate ML-DSA-87 CSR
 * mvn compile exec:java -Dexec.args="ML-DSA-87"
 *
 * // Generate all supported algorithms
 * mvn compile exec:java -Dexec.args="--all"
 *
 * // Custom subject and output directory
 * mvn compile exec:java -Dexec.args="ML-DSA-65" \
 *     -Dcsr.subject="CN=My App,O=My Company,C=US" \
 *     -Dcsr.outdir="./certs"
 * }</pre>
 *
 * @see <a href="https://www.bouncycastle.org/documentation/documentation-java/">Bouncy Castle Docs</a>
 * @see <a href="https://csrc.nist.gov/projects/post-quantum-cryptography">NIST PQC Project</a>
 */
public class PqcCsrGenerator {

	// ── Configuration ────────────────────────────────────────────────

	/** Default subject DN for generated CSRs. Override via system property {@code csr.subject}. */
	private static final String SUBJECT_DN =
			System.getProperty("csr.subject", "CN=Test Certificate,O=Example Org,C=US");

	/** Output directory for generated files. Override via system property {@code csr.outdir}. */
	private static final Path OUTPUT_DIR =
			Path.of(System.getProperty("csr.outdir", "."));

	/** Optional comma-separated SANs. Override via system property {@code csr.san}. */
	private static final String SUBJECT_ALT_NAMES =
			System.getProperty("csr.san", "");

	// ── Algorithm registry ───────────────────────────────────────────

	/**
	 * Algorithm configuration record.
	 *
	 * @param kpgAlg    JCA KeyPairGenerator algorithm name
	 * @param paramSpec algorithm parameters (null if none required)
	 * @param signerAlg signature algorithm name for CSR signing
	 */
	private record AlgConfig(String kpgAlg, AlgorithmParameterSpec paramSpec, String signerAlg) {}

	private static final Map<String, AlgConfig> ALGORITHMS = new LinkedHashMap<>();

	static {
		// ── ML-DSA (FIPS 204) — Lattice-based, NIST standard ─────────
		// Security levels: 44 ≈ AES-128, 65 ≈ AES-192, 87 ≈ AES-256
		ALGORITHMS.put("ML-DSA-44", new AlgConfig("ML-DSA", MLDSAParameterSpec.ml_dsa_44, "ML-DSA"));
		ALGORITHMS.put("ML-DSA-65", new AlgConfig("ML-DSA", MLDSAParameterSpec.ml_dsa_65, "ML-DSA"));
		ALGORITHMS.put("ML-DSA-87", new AlgConfig("ML-DSA", MLDSAParameterSpec.ml_dsa_87, "ML-DSA"));

		// ── SLH-DSA (FIPS 205) — Hash-based, NIST standard ──────────
		// Variants: SHA2 vs SHAKE (hash function), f = fast signing, s = small signature
		ALGORITHMS.put("SLH-DSA-SHA2-128f",  new AlgConfig("SLH-DSA", SLHDSAParameterSpec.slh_dsa_sha2_128f,  "SLH-DSA"));
		ALGORITHMS.put("SLH-DSA-SHA2-128s",  new AlgConfig("SLH-DSA", SLHDSAParameterSpec.slh_dsa_sha2_128s,  "SLH-DSA"));
		ALGORITHMS.put("SLH-DSA-SHA2-192f",  new AlgConfig("SLH-DSA", SLHDSAParameterSpec.slh_dsa_sha2_192f,  "SLH-DSA"));
		ALGORITHMS.put("SLH-DSA-SHA2-192s",  new AlgConfig("SLH-DSA", SLHDSAParameterSpec.slh_dsa_sha2_192s,  "SLH-DSA"));
		ALGORITHMS.put("SLH-DSA-SHA2-256f",  new AlgConfig("SLH-DSA", SLHDSAParameterSpec.slh_dsa_sha2_256f,  "SLH-DSA"));
		ALGORITHMS.put("SLH-DSA-SHA2-256s",  new AlgConfig("SLH-DSA", SLHDSAParameterSpec.slh_dsa_sha2_256s,  "SLH-DSA"));
		ALGORITHMS.put("SLH-DSA-SHAKE-128f", new AlgConfig("SLH-DSA", SLHDSAParameterSpec.slh_dsa_shake_128f, "SLH-DSA"));
		ALGORITHMS.put("SLH-DSA-SHAKE-128s", new AlgConfig("SLH-DSA", SLHDSAParameterSpec.slh_dsa_shake_128s, "SLH-DSA"));
		ALGORITHMS.put("SLH-DSA-SHAKE-192f", new AlgConfig("SLH-DSA", SLHDSAParameterSpec.slh_dsa_shake_192f, "SLH-DSA"));
		ALGORITHMS.put("SLH-DSA-SHAKE-192s", new AlgConfig("SLH-DSA", SLHDSAParameterSpec.slh_dsa_shake_192s, "SLH-DSA"));
		ALGORITHMS.put("SLH-DSA-SHAKE-256f", new AlgConfig("SLH-DSA", SLHDSAParameterSpec.slh_dsa_shake_256f, "SLH-DSA"));
		ALGORITHMS.put("SLH-DSA-SHAKE-256s", new AlgConfig("SLH-DSA", SLHDSAParameterSpec.slh_dsa_shake_256s, "SLH-DSA"));

		// ── Falcon / FN-DSA — Lattice (FFT/NTRU), pending NIST standardization ───
		ALGORITHMS.put("FALCON-512",  new AlgConfig("Falcon", FalconParameterSpec.falcon_512,  "FALCON-512"));
		ALGORITHMS.put("FALCON-1024", new AlgConfig("Falcon", FalconParameterSpec.falcon_1024, "FALCON-1024"));

		// ── Classical algorithms (for comparison / hybrid use) ────────
		ALGORITHMS.put("Ed25519",  new AlgConfig("Ed25519", null, "Ed25519"));
		ALGORITHMS.put("Ed448",    new AlgConfig("Ed448",   null, "Ed448"));
		ALGORITHMS.put("EC-P256",  new AlgConfig("EC", new ECGenParameterSpec("P-256"), "SHA256withECDSA"));
		ALGORITHMS.put("EC-P384",  new AlgConfig("EC", new ECGenParameterSpec("P-384"), "SHA384withECDSA"));
		ALGORITHMS.put("RSA-2048", new AlgConfig("RSA", new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4), "SHA256withRSA"));
		ALGORITHMS.put("RSA-3072", new AlgConfig("RSA", new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4), "SHA256withRSA"));
		ALGORITHMS.put("RSA-4096", new AlgConfig("RSA", new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4), "SHA256withRSA"));
	}

	// ══════════════════════════════════════════════════════════════════
	// MAIN ENTRY POINT
	// ══════════════════════════════════════════════════════════════════

	public static void main(String[] args) {
		try {
			run(args);
		} catch (IllegalArgumentException e) {
			System.err.println("Error: " + e.getMessage());
			printUsage();
			System.exit(1);
		} catch (Exception e) {
			System.err.println("Fatal error: " + e.getMessage());
			e.printStackTrace();
			System.exit(2);
		}
	}

	/**
	 * Main application logic, separated for cleaner error handling.
	 */
	private static void run(String[] args) throws Exception {
		ensureProviders();
		ensureOutputDirectory();

		// Parse command-line argument
		if (args.length < 1 || "--list".equalsIgnoreCase(args[0]) || "--help".equalsIgnoreCase(args[0])) {
			printUsage();
			return;
		}

		// Handle --all flag
		if ("--all".equalsIgnoreCase(args[0])) {
			generateAll();
			return;
		}

		// Resolve algorithm (exact match, then case-insensitive)
		String algName = resolveAlgorithmName(args[0]);
		if (algName == null) {
			throw new IllegalArgumentException("Unknown algorithm: " + args[0]);
		}

		generateAndSave(algName, ALGORITHMS.get(algName));
	}

	// ══════════════════════════════════════════════════════════════════
	// CORE OPERATIONS
	// ══════════════════════════════════════════════════════════════════

	/**
	 * Generates CSRs for all supported algorithms.
	 */
	private static void generateAll() {
		System.out.println("Generating CSRs for all " + ALGORITHMS.size() + " algorithms...\n");

		int success = 0;
		int failed = 0;

		for (Map.Entry<String, AlgConfig> entry : ALGORITHMS.entrySet()) {
			String algName = entry.getKey();
			try {
				System.out.println("\n" + "═".repeat(60));
				generateAndSave(algName, entry.getValue());
				success++;
			} catch (Exception e) {
				System.err.println("[!] Failed to generate " + algName + ": " + e.getMessage());
				failed++;
			}
		}

		System.out.println("\n" + "═".repeat(60));
		System.out.println("Summary: " + success + " succeeded, " + failed + " failed");
	}

	/**
	 * Generates a key pair and CSR for the specified algorithm, then saves to files.
	 *
	 * @param algName display name of the algorithm
	 * @param config  algorithm configuration
	 */
	private static void generateAndSave(String algName, AlgConfig config) throws Exception {
		// 1. Generate key pair
		System.out.println("[*] Generating " + algName + " key pair...");
		KeyPair keyPair = generateKeyPair(config);

		System.out.println("[+] Key pair generated.");
		System.out.println("    Algorithm       : " + keyPair.getPublic().getAlgorithm());
		System.out.println("    Public key size : " + keyPair.getPublic().getEncoded().length + " bytes");
		System.out.println("    Private key size: " + keyPair.getPrivate().getEncoded().length + " bytes");

		// 2. Build CSR (with SANs if configured)
		System.out.println("\n[*] Building PKCS#10 CSR for: " + SUBJECT_DN);

		PKCS10CertificationRequest csr;
		if (!SUBJECT_ALT_NAMES.isBlank()) {
			String[] sanStrings = SUBJECT_ALT_NAMES.split(",");
			GeneralName[] sanNames = new GeneralName[sanStrings.length];

			for (int i = 0; i < sanStrings.length; i++) {
				String name = sanStrings[i].trim();
				sanNames[i] = parseGeneralName(name);
			}

			System.out.println("    Subject Alt Names: " + Arrays.toString(sanStrings));
			// Pass the parsed GeneralName array to your builder
			csr = buildCsrWithExtensions(keyPair, config.signerAlg(), sanNames);
		} else {
			csr = buildCsr(keyPair, config.signerAlg());
		}

		System.out.println("[+] CSR created and self-signed.");

		// 3. Derive output filenames
		String base = algName.toLowerCase().replace("-", "_");
		Path csrPath = OUTPUT_DIR.resolve(base + ".csr");
		Path keyPath = OUTPUT_DIR.resolve(base + "_private.pem");

		// 4. Write CSR
		writePem(csr, csrPath);
		System.out.println("[+] CSR written to " + csrPath);

		// 5. Write private key (handle ML-DSA expanded form)
		PrivateKey privKeyToWrite = preparePrivateKeyForExport(keyPair.getPrivate());
		writePem(privKeyToWrite, keyPath);
		System.out.println("[+] Private key written to " + keyPath);

		// 6. Verify CSR signature
		boolean valid = csr.isSignatureValid(
				new JcaContentVerifierProviderBuilder()
						.setProvider("BC")
						.build(csr.getSubjectPublicKeyInfo()));

		System.out.println("\n[+] CSR signature verification: " + (valid ? "PASSED ✓" : "FAILED ✗"));

		// 7. Print CSR PEM
		System.out.println("\n" + "─".repeat(60));
		System.out.println("CSR (PEM):");
		System.out.println("─".repeat(60));
		System.out.print(toPem(csr));
	}

	// ══════════════════════════════════════════════════════════════════
	// KEY PAIR GENERATION
	// ══════════════════════════════════════════════════════════════════

	/**
	 * Generates a key pair for the specified algorithm configuration.
	 *
	 * @param config algorithm configuration
	 * @return generated key pair
	 * @throws Exception if key generation fails
	 */
	private static KeyPair generateKeyPair(AlgConfig config) throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(config.kpgAlg(), "BC");
		if (config.paramSpec() != null) {
			kpg.initialize(config.paramSpec(), new SecureRandom());
		}
		return kpg.generateKeyPair();
	}

	/**
	 * Prepares a private key for export, handling algorithm-specific requirements.
	 *
	 * <p>ML-DSA private keys can be stored in seed form (32 bytes) or expanded form.
	 * The expanded form is required for repeated signing without re-expansion cost,
	 * and provides better interoperability with tools expecting full keys.</p>
	 *
	 * @param privateKey the private key to prepare
	 * @return the key ready for PEM export
	 */
	private static PrivateKey preparePrivateKeyForExport(PrivateKey privateKey) {
		if (privateKey instanceof MLDSAPrivateKey mldsaKey) {
			// false = expanded form (not seed-only)
			PrivateKey expanded = mldsaKey.getPrivateKey(false);
			System.out.println("    Expanded ML-DSA key: " + expanded.getEncoded().length + " bytes");
			return expanded;
		}
		return privateKey;
	}

	// ══════════════════════════════════════════════════════════════════
	// CSR BUILDING
	// ══════════════════════════════════════════════════════════════════

	/**
	 * Parses a string to determine the correct X.509 GeneralName tag.
	 * * <p>This method evaluates the input string to identify its format and maps it
	 * to the corresponding X.509 GeneralName type. It supports IP addresses (v4/v6),
	 * URIs, Email addresses (RFC822), and defaults to DNS names.</p>
	 * * @param name The string representation of the Subject Alternative Name (SAN).
	 * @return A {@link GeneralName} object configured with the identified type tag.
	 */
	private static GeneralName parseGeneralName(String name) {
		// 1. Check for IP Address (v4 or v6)
		if (name.matches("^[0-9a-fA-F.:]+$") && (name.contains(".") || name.contains(":"))) {
			return new GeneralName(GeneralName.iPAddress, name);
		}
		// 2. Check for URI
		if (name.contains("://")) {
			return new GeneralName(GeneralName.uniformResourceIdentifier, name);
		}
		// 3. Check for Email (RFC822)
		if (name.contains("@") && !name.contains("/")) {
			return new GeneralName(GeneralName.rfc822Name, name);
		}
		// 4. Default to DNS
		return new GeneralName(GeneralName.dNSName, name);
	}

	/**
	 * Builds a basic PKCS#10 CSR for the given key pair.
	 *
	 * @param keyPair the key pair (public key goes in CSR, private key signs it)
	 * @param sigAlg signature algorithm name
	 * @return the CSR
	 * @throws Exception if CSR building fails
	 */
	private static PKCS10CertificationRequest buildCsr(
			KeyPair keyPair, String sigAlg) throws Exception {

		ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
				.build(keyPair.getPrivate());

		return new JcaPKCS10CertificationRequestBuilder(
				new X500Name(PqcCsrGenerator.SUBJECT_DN),
				keyPair.getPublic()
		).build(signer);
	}

	/**
	 * Builds a PKCS#10 Certification Request (CSR) including X.509 extensions.
	 *
	 * <p>This method constructs the CSR using the provided key pair and subject DN,
	 * then adds the requested extensions (such as Subject Alternative Names) to the attribute set before signing the
	 * request with the specified algorithm.</p>
	 *
	 * @param keyPair The {@link KeyPair} containing the public key for the CSR and the private key used for signing.
	 * @param sigAlg The signing algorithm to be used (e.g., "ML-DSA-65").
	 * @param sans An array of {@link GeneralName} objects to be included in the Subject Alternative Name extension.
	 * @return A signed {@link PKCS10CertificationRequest} object.
	 * @throws Exception if there is an error building the extension request or signing the CSR.
	 */
	private static PKCS10CertificationRequest buildCsrWithExtensions(KeyPair keyPair, String sigAlg,
			GeneralName[] sans) throws Exception {

		ExtensionsGenerator extGen = new ExtensionsGenerator();
		extGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));

		PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
				new X500Name(PqcCsrGenerator.SUBJECT_DN),
				keyPair.getPublic()
		);

		builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

		ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
				.setProvider("BCPQC")
				.build(keyPair.getPrivate());

		return builder.build(signer);
	}

	// ══════════════════════════════════════════════════════════════════
	// PROVIDER & ENVIRONMENT SETUP
	// ══════════════════════════════════════════════════════════════════

	/**
	 * Registers Bouncy Castle providers if not already present.
	 * This is idempotent and safe to call multiple times.
	 */
	private static void ensureProviders() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastlePQCProvider());
		}
	}

	/**
	 * Ensures the output directory exists, creating it if necessary.
	 */
	private static void ensureOutputDirectory() throws Exception {
		if (!Files.exists(OUTPUT_DIR)) {
			Files.createDirectories(OUTPUT_DIR);
			System.out.println("[*] Created output directory: " + OUTPUT_DIR.toAbsolutePath());
		}
	}

	/**
	 * Resolves an algorithm name, supporting case-insensitive matching.
	 *
	 * @param input user-provided algorithm name
	 * @return canonical algorithm name, or null if not found
	 */
	private static String resolveAlgorithmName(String input) {
		// Try exact match first
		if (ALGORITHMS.containsKey(input)) {
			return input;
		}
		// Fall back to case-insensitive
		for (String name : ALGORITHMS.keySet()) {
			if (name.equalsIgnoreCase(input)) {
				return name;
			}
		}
		return null;
	}

	// ══════════════════════════════════════════════════════════════════
	// PEM I/O UTILITIES
	// ══════════════════════════════════════════════════════════════════

	/**
	 * Writes any BC/JCA object to a PEM file.
	 *
	 * @param obj      object to write (CSR, key, certificate, etc.)
	 * @param filepath destination path
	 * @throws Exception if writing fails
	 */
	private static void writePem(Object obj, Path filepath) throws Exception {
		try (JcaPEMWriter pw = new JcaPEMWriter(Files.newBufferedWriter(filepath))) {
			pw.writeObject(obj);
		}
	}

	/**
	 * Renders any BC/JCA object as a PEM string.
	 *
	 * @param obj object to render
	 * @return PEM-encoded string
	 * @throws Exception if rendering fails
	 */
	private static String toPem(Object obj) throws Exception {
		StringWriter sw = new StringWriter();
		try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
			pw.writeObject(obj);
		}
		return sw.toString();
	}

	// ══════════════════════════════════════════════════════════════════
	// USAGE / HELP
	// ══════════════════════════════════════════════════════════════════

	/**
	 * Prints usage information and available algorithms.
	 */
	private static void printUsage() {
		System.out.println("""
            
            Usage: PqcCsrGenerator <algorithm>
                   PqcCsrGenerator --all
                   PqcCsrGenerator --list | --help
            
            Options:
              <algorithm>   Generate CSR for the specified algorithm
              --all         Generate CSRs for all supported algorithms
              --list        List all supported algorithms
              --help        Show this help message
            
            System Properties:
              -Dcsr.subject="CN=...,O=...,C=..."   Subject DN (default: CN=Test Certificate,O=Example Org,C=US)
              -Dcsr.outdir="/path/to/dir"         Output directory (default: current directory)
              -Dcsr.san="a.com,b.com"             Comma-separated Subject Alt Names (optional)
            
            Supported Algorithms:
            ─────────────────────────────────────────────────────────────
            """);

		String lastFamily = "";
		for (Map.Entry<String, AlgConfig> e : ALGORITHMS.entrySet()) {
			String family = e.getValue().kpgAlg();
			if (!family.equals(lastFamily)) {
				if (!lastFamily.isEmpty()) {
					System.out.println();
				}
				System.out.println("  " + family + ":");
				lastFamily = family;
			}
			System.out.println("    • " + e.getKey());
		}

		System.out.println("""
            
            Examples:
              mvn compile exec:java -Dexec.args="ML-DSA-87"
              mvn compile exec:java -Dexec.args="SLH-DSA-SHA2-128f"
              mvn compile exec:java -Dexec.args="FALCON-512"
              mvn compile exec:java -Dexec.args="--all"
              mvn compile exec:java -Dexec.args="EC-P256" -Dcsr.san="example.com,www.example.com"
            """);
	}
}