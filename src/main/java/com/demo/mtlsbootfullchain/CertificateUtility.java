package com.demo.mtlsbootfullchain;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.core.io.ClassPathResource;

public class CertificateUtility {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
            throws OperatorCreationException, CertIOException, CertificateException {
        // Define issuer and subject details
        X500Name issuer = new X500Name(dn);
        X500Name subject = issuer;

        // Validity period for the certificate
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date notAfter = new Date(System.currentTimeMillis() + (long) days * 24 * 60 * 60 * 1000);

        // Generate certificate serial number
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        // Create certificate builder
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                pair.getPublic()
        );

        // Add extensions
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true)); // CA flag
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        // Sign the certificate
        ContentSigner signer = new JcaContentSignerBuilder(algorithm)
                .setProvider("BC").build(pair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }

    public static X509Certificate generateSignedCertificate(String dn, KeyPair pair, int days, String algorithm,
                                                            X509Certificate caCert, PrivateKey caPrivateKey) throws Exception {
        X500Principal subject = new X500Principal(dn);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                caCert.getSubjectX500Principal(),
                BigInteger.valueOf(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000),
                new Date(System.currentTimeMillis() + days * 24L * 60L * 60L * 1000L),
                subject,
                pair.getPublic()
        );

        // Add extensions
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false)); // Not a CA
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        ContentSigner signer = new JcaContentSignerBuilder(algorithm).setProvider("BC").build(caPrivateKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
    }

    public static void saveToPemFile(String filename, Object object) throws Exception {
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filename))) {
            if (object instanceof PrivateKey) {
                pemWriter.writeObject(new JcaPKCS8Generator((PrivateKey) object, null));
            }
            else {
                pemWriter.writeObject(object);
            }
        }
    }

    public static String convertToPem(Object object) throws IOException {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            if (object instanceof PrivateKey) {
                pemWriter.writeObject(new JcaPKCS8Generator((PrivateKey) object, null));
            }
            else
            {
                pemWriter.writeObject(object);
            }
        }
        return writer.toString();
    }

    public static Object loadFromPemFile(String filename, Class<?> clazz) throws IOException {
        if (clazz == X509Certificate.class) {
            try (FileInputStream fis = new FileInputStream(filename)) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                return (X509Certificate) cf.generateCertificate(fis);
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            }
        } else if (clazz == PrivateKey.class) {
            try (PemReader pemReader = new PemReader(new FileReader(filename))) {
                PemObject pemObject = pemReader.readPemObject();
                byte[] pemContent = pemObject.getContent();
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemContent);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePrivate(keySpec);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        }
        throw new IllegalArgumentException("Unsupported class: " + clazz.getName());
    }

    public static Object loadFromResource(String filename, Class<?> clazz) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ClassPathResource resource = new ClassPathResource(filename);
        if (clazz == X509Certificate.class) {
            try (InputStream inputStream = resource.getInputStream()) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                return (X509Certificate) cf.generateCertificate(inputStream);
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            }
        } else if (clazz == PrivateKey.class) {
            // Load and decode the private key
            String key = new String(Files.readAllBytes(Paths.get(resource.getURI())));
            String privateKeyPEM = key
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");

            // Decode and generate the private key
            byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Use "EC" for EC keys, etc.
            return keyFactory.generatePrivate(keySpec);
        }
        throw new IllegalArgumentException("Unsupported class: " + clazz.getName());
    }

    public static X509Certificate loadCertificateFromString(String certificateString) throws Exception {
        // Clean up the certificate string and decode it
        String certPEM = certificateString
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");

        byte[] decodedCert = Base64.getDecoder().decode(certPEM);

        // Generate the X509Certificate instance
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(new java.io.ByteArrayInputStream(decodedCert));
    }

    public static PrivateKey loadPrivateKeyFromString(String privateKeyString) throws Exception {
        // Clean up the private key string and decode it
        String privateKeyPEM = privateKeyString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);

        // Generate the PrivateKey instance
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Adjust for key type, e.g., "EC" for elliptic curve
        return keyFactory.generatePrivate(keySpec);
    }

    public static String convertPKCS1ToPKCS8(String privateKeyPEM) throws Exception {
        PEMParser pemParser = new PEMParser(new StringReader(privateKeyPEM));
        Object pemObject = pemParser.readObject();

        // PEMKeyPair'den özel anahtarı al
        PrivateKeyInfo privateKeyInfo;
        if (pemObject instanceof PEMKeyPair) {
            privateKeyInfo = ((PEMKeyPair) pemObject).getPrivateKeyInfo();
        } else {
            throw new IllegalArgumentException("Geçersiz PEM formatı. Beklenen PEMKeyPair.");
        }

        // PKCS#8 formatına çevir
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        // Geri PEM formatına dönüştür
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
        pemWriter.writeObject(new JcaPKCS8Generator(privateKey, null));
        // pemWriter.writeObject(privateKey);
        pemWriter.close();

        return stringWriter.toString();
    }
}