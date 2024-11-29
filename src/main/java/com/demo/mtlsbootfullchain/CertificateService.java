package com.demo.mtlsbootfullchain;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

@Service
public class CertificateService {

    private static final String CA_CERT_PATH = "ca-cert.pem";
    private static final String CA_KEY_PATH = "ca-key.pem";
    private static final String SERVER_CERT_PATH = "server-cert.pem";
    private static final String SERVER_KEY_PATH = "server-key.pem";
    private static final String CLIENT_CERT_PATH = "client-cert.pem";
    private static final String CLIENT_KEY_PATH = "client-key.pem";
    private static final String CLIENT_DN = "CN=Client, O=xxx, L=Istanbul, C=Turkey";
    private static final String CA_DN = "CN=mtlsdev.xxx.com, O=xxx, L=Istanbul, C=Turkey";
    private static final String SERVER_DN = "CN=mtlsdev.xxx.com, O=xxx, L=Istanbul, C=Turkey";

    private static final String CA_CERTIFICATE = "";

    private static final String CA_PRIVATE_KEY = "";

    private static X509Certificate caCert;
    private static PrivateKey caPrivateKey;

    static {
        Security.addProvider(new BouncyCastleProvider());
        try {
            caCert = CertificateUtility.loadCertificateFromString(CA_CERTIFICATE);
            caPrivateKey = CertificateUtility.loadPrivateKeyFromString(CA_PRIVATE_KEY);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void generateCACertificate() {
        try {
            KeyPair keyPair = CertificateUtility.generateKeyPair();
            X509Certificate certificate = CertificateUtility.generateCertificate(
                    CA_DN, keyPair, 365, "SHA256withRSA"
            );

            new File("certificates").mkdirs(); // Ensure the directory exists
            CertificateUtility.saveToPemFile(CA_CERT_PATH, certificate);
            CertificateUtility.saveToPemFile(CA_KEY_PATH, keyPair.getPrivate());
        } catch (Exception e) {
            throw new RuntimeException("Error generating CA certificate", e);
        }
    }

    public void generateServerCertificate() {
        try {
            KeyPair serverKeyPair = CertificateUtility.generateKeyPair();
            X509Certificate caCert = (X509Certificate) CertificateUtility.loadFromPemFile(CA_CERT_PATH, X509Certificate.class);
            PrivateKey caPrivateKey = (PrivateKey) CertificateUtility.loadFromPemFile(CA_KEY_PATH, PrivateKey.class);

            X509Certificate serverCertificate = CertificateUtility.generateSignedCertificate(
                    SERVER_DN, serverKeyPair, 365, "SHA256withRSA", caCert, caPrivateKey
            );

            CertificateUtility.saveToPemFile(SERVER_CERT_PATH, serverCertificate);
            CertificateUtility.saveToPemFile(SERVER_KEY_PATH, serverKeyPair.getPrivate());
        } catch (Exception e) {
            throw new RuntimeException("Error generating server certificate", e);
        }
    }

    public ClientCertficiateData generateClientCertificate() {
        try {
            KeyPair clientKeyPair = CertificateUtility.generateKeyPair();
            X509Certificate clientCertificate = CertificateUtility.generateSignedCertificate(
                    CLIENT_DN, clientKeyPair, 365, "SHA256withRSA", caCert, caPrivateKey
            );

//            CertificateUtility.saveToPemFile(CLIENT_CERT_PATH, clientCertificate);
//            CertificateUtility.saveToPemFile(CLIENT_KEY_PATH, clientKeyPair.getPrivate());

            return new ClientCertficiateData(CertificateUtility.convertToPem(clientCertificate), CertificateUtility.convertToPem(clientKeyPair.getPrivate()));
        } catch (Exception e) {
            throw new RuntimeException("Error generating client certificate", e);
        }
    }
}
