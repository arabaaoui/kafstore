import forge from 'node-forge';

export interface CertificateInfo {
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  isRoot: boolean;
  index: number;
}

export interface GeneratedStores {
  keystoreP12: Uint8Array;
  caRootPem: string;
  caChainPem: string;
  properties: string;
  createTruststoreScript: string;
}

/**
 * Parse PEM certificates from a chain
 */
export function parseCertificateChain(pemContent: string): forge.pki.Certificate[] {
  const certs: forge.pki.Certificate[] = [];
  const pemRegex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const matches = pemContent.match(pemRegex);

  if (matches) {
    for (const pem of matches) {
      try {
        const cert = forge.pki.certificateFromPem(pem);
        certs.push(cert);
      } catch (e) {
        console.error('Failed to parse certificate:', e);
      }
    }
  }

  return certs;
}

/**
 * Get certificate info for display
 */
export function getCertificateInfo(cert: forge.pki.Certificate, index: number): CertificateInfo {
  const subjectAttrs = cert.subject.attributes.map(
    attr => `${attr.shortName || attr.name}=${attr.value}`
  ).join(', ');

  const issuerAttrs = cert.issuer.attributes.map(
    attr => `${attr.shortName || attr.name}=${attr.value}`
  ).join(', ');

  const isRoot = subjectAttrs === issuerAttrs;

  return {
    subject: subjectAttrs,
    issuer: issuerAttrs,
    notBefore: cert.validity.notBefore.toISOString(),
    notAfter: cert.validity.notAfter.toISOString(),
    isRoot,
    index,
  };
}

/**
 * Analyze a certificate chain and return info about each certificate
 */
export function analyzeCertificateChain(pemContent: string): CertificateInfo[] {
  const certs = parseCertificateChain(pemContent);
  return certs.map((cert, index) => getCertificateInfo(cert, index));
}

/**
 * Extract the root certificate (first self-signed or first in chain)
 */
export function extractRootCert(pemContent: string): forge.pki.Certificate | null {
  const certs = parseCertificateChain(pemContent);
  if (certs.length === 0) return null;

  // Find root (self-signed) certificate
  for (const cert of certs) {
    const subject = cert.subject.attributes.map(a => `${a.shortName}=${a.value}`).join(',');
    const issuer = cert.issuer.attributes.map(a => `${a.shortName}=${a.value}`).join(',');
    if (subject === issuer) {
      return cert;
    }
  }

  // If no self-signed, return the first one (usually root is first in chain)
  return certs[0];
}

/**
 * Parse a PEM private key
 */
export function parsePrivateKey(pemContent: string): forge.pki.PrivateKey {
  // Handle encrypted keys
  if (pemContent.includes('ENCRYPTED')) {
    throw new Error('Encrypted private keys are not supported. Please decrypt your key first.');
  }

  // Try to parse as RSA private key
  try {
    return forge.pki.privateKeyFromPem(pemContent);
  } catch (e) {
    throw new Error('Failed to parse private key. Make sure it\'s in PEM format.');
  }
}

/**
 * Generate a PKCS#12 keystore containing the certificate chain and private key
 */
export function generateKeystoreP12(
  certPem: string,
  keyPem: string,
  bundlePem: string,
  alias: string,
  password: string
): Uint8Array {
  // Parse certificate
  const certs = parseCertificateChain(certPem);
  if (certs.length === 0) {
    throw new Error('No certificate found in cert file');
  }
  const cert = certs[0];

  // Parse private key
  const privateKey = parsePrivateKey(keyPem);

  // Parse bundle (CA chain)
  const bundleCerts = parseCertificateChain(bundlePem);

  // Create PKCS#12
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    privateKey as any,
    [cert, ...bundleCerts],
    password,
    {
      algorithm: '3des',
      friendlyName: alias,
    }
  );

  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
  return new Uint8Array(p12Der.split('').map(c => c.charCodeAt(0)));
}

/**
 * Extract the root CA certificate as PEM string
 */
export function extractRootCaPem(caChainPem: string): string {
  const rootCert = extractRootCert(caChainPem);
  if (!rootCert) {
    throw new Error('No root certificate found in CA chain');
  }
  return forge.pki.certificateToPem(rootCert);
}

/**
 * Generate shell script to create truststore.jks using keytool
 */
export function generateTruststoreScript(alias: string, password: string): string {
  return `#!/bin/bash
# Script to create truststore.jks from CA_root.pem
# Requires: Java keytool (included with JDK/JRE)

keytool -import -file CA_root.pem -alias ${alias}-ca \\
  -keystore truststore.jks -storepass ${password} -noprompt

echo "Created truststore.jks"
echo "You can verify with: keytool -list -keystore truststore.jks -storepass ${password}"
`;
}

/**
 * Generate Kafka SSL properties file content
 */
export function generatePropertiesFile(
  bootstrapServer: string,
  keystorePath: string,
  password: string
): string {
  return `# Kafka SSL Configuration
# Generated by mTLS Configurator (Client-Side)
# All cryptographic operations were performed locally in your browser.
# Your private keys never left your machine.

security.protocol=SSL

# Truststore (JKS) - created via: ./create-truststore.sh
ssl.truststore.location=/path/to/truststore.jks
ssl.truststore.password=${password}

# Keystore (PKCS12) - generated client-side
ssl.keystore.location=${keystorePath}
ssl.keystore.password=${password}
ssl.keystore.type=PKCS12
ssl.key.password=${password}

ssl.endpoint.identification.algorithm=

# Bootstrap server
bootstrap.servers=${bootstrapServer}
`;
}

/**
 * Main function to generate all stores from certificates
 */
export function generateStores(
  caChainPem: string,
  certPem: string,
  keyPem: string,
  bundlePem: string,
  alias: string,
  password: string,
  bootstrapServer: string
): GeneratedStores {
  // Generate keystore (certificate + private key + chain)
  const keystoreP12 = generateKeystoreP12(certPem, keyPem, bundlePem, alias, password);

  // Extract root CA for truststore creation
  const caRootPem = extractRootCaPem(caChainPem);

  // Generate script to create truststore.jks
  const createTruststoreScript = generateTruststoreScript(alias, password);

  // Generate properties file
  const properties = generatePropertiesFile(
    bootstrapServer,
    '/path/to/keystore.p12',
    password
  );

  return {
    keystoreP12,
    caRootPem,
    caChainPem,
    properties,
    createTruststoreScript,
  };
}
