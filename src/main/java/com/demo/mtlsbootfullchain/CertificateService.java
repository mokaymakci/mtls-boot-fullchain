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
    private static final String CLIENT_DN = "CN=Client, O=FUPSBank, L=Istanbul, C=Turkey";
    private static final String CA_DN = "CN=mtlsdev.fupsbank.com, O=FUPSBank, L=Istanbul, C=Turkey";
    private static final String SERVER_DN = "CN=mtlsdev.fupsbank.com, O=FUPSBank, L=Istanbul, C=Turkey";

    private static final String CA_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDTzCCAjegAwIBAgIGAZLdpCm5MA0GCSqGSIb3DQEBCwUAMFYxHTAbBgNVBAMM\n" +
            "FG10bHNkZXYuZnVwc2JhbmsuY29tMREwDwYDVQQKDAhGVVBTQmFuazERMA8GA1UE\n" +
            "BwwISXN0YW5idWwxDzANBgNVBAYTBlR1cmtleTAeFw0yNDEwMjkxMzM2MTZaFw0y\n" +
            "NTEwMzAxMzM2MTZaMFYxHTAbBgNVBAMMFG10bHNkZXYuZnVwc2JhbmsuY29tMREw\n" +
            "DwYDVQQKDAhGVVBTQmFuazERMA8GA1UEBwwISXN0YW5idWwxDzANBgNVBAYTBlR1\n" +
            "cmtleTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJJNOH5doZLCQirJ\n" +
            "J0irnwx8hXR3GGEu1mw66Sx44cxM2gtbIjd/asryHryhnPDdA2xo6Hxb09EXDWok\n" +
            "jHBXG4tFqB4BQ3AKPhzcdxjsELHCqvyTFIUM8ZGLMNscSPPbLs251/x+yC7/2EVA\n" +
            "IJpMYpoMWYDBZ4bMbxlRSph2yzV91CAgq8cFQg6rFYpNnNQzUQAscLqKvoSyfud7\n" +
            "9aJtW4FV0Pr4PsU4eSs8MngG/WQspt77S41B9JGmSKTiW9BH59BW7PHKEm3WdDzO\n" +
            "1IvhJVa9LheVbYc4HbPGS56u+FRtQdHY1C/W5nqWVzsbJ4LWi5/HwvpO9mLDyzcd\n" +
            "1826D7kCAwEAAaMjMCEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\n" +
            "DQYJKoZIhvcNAQELBQADggEBAEfe/1ChRopM2MGzKq1229sgINH67L1pm7Djk84e\n" +
            "bhOVPCVMwqM3VZjRk2lG6HaJJSUn2dkykxTcya7rz88UMXSeMlKJJGbF0Wql8zId\n" +
            "sMQxta2O3yg4UVFFI6YrhXYzSjPA7n4P5jld391rIjscwpFjnXuuwfbwvmzyMxmp\n" +
            "eDNEvJUTyn+m1p8rs1iBgBeWtw6xhfOsKeurfsoSLQT82Ip58XVdhU3RcOMlqR1R\n" +
            "XOpXOvlibIl/Lzkfvup1kqrdJRk7TPFDD47i+yEpLA0DbHxJQqBwz1XzQHuk0slv\n" +
            "8uEeuXtBmnSM9GjKWOz261kWSc3Z37QmxUoqVvpkqNywzc4=\n" +
            "-----END CERTIFICATE-----\n";

    private static final String CA_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCSTTh+XaGSwkIq\n" +
            "ySdIq58MfIV0dxhhLtZsOukseOHMTNoLWyI3f2rK8h68oZzw3QNsaOh8W9PRFw1q\n" +
            "JIxwVxuLRageAUNwCj4c3HcY7BCxwqr8kxSFDPGRizDbHEjz2y7Nudf8fsgu/9hF\n" +
            "QCCaTGKaDFmAwWeGzG8ZUUqYdss1fdQgIKvHBUIOqxWKTZzUM1EALHC6ir6Esn7n\n" +
            "e/WibVuBVdD6+D7FOHkrPDJ4Bv1kLKbe+0uNQfSRpkik4lvQR+fQVuzxyhJt1nQ8\n" +
            "ztSL4SVWvS4XlW2HOB2zxkuervhUbUHR2NQv1uZ6llc7GyeC1oufx8L6TvZiw8s3\n" +
            "HdfNug+5AgMBAAECggEAH8sMNdnfHOd+PZINKWuyWqJM1ixzbdsh2c9LkNCMMTua\n" +
            "PtGFNA5KhOPs7g0o7+b3sX1y2GOUOmIKFkDvDBLB95ghmrOnlheDu/3lG9NhJWAq\n" +
            "jEziLq/LZ1eaPGN/Lw84sphqaYKbuir7MsFm1GE5JET+xk5BUzfmBNh3n35hVrQ3\n" +
            "YD4A+XXp3m52ee116g3XaB5AxCdrmWrFkedvqKJzkElv4R8VAMsEWJ1qbti864oE\n" +
            "StBg4mdPaQZYi/4ZK6d1Sq417GYEL10uNgOwF6FYtEsaIyo38lPmdq51QsqqJEEY\n" +
            "KOKzOgcdW35FY+hlwc5tYhW1hEPSgneOyT/Q/sxyaQKBgQDD7BVDa+nhaiJ2TXZV\n" +
            "oiWVK3Z/prhja/W1APjEuzuXJCru8oImToM3604ZbKtlZiUD7OmbTGeaiBubCwuN\n" +
            "KTQjSADcdw82IsVnMh2MNVHqlftjEI154gFcIAhELebGId9ZBbrI8RyFDzftDuOW\n" +
            "h6bBQMTfVMUr64nXcJgdK+G1FwKBgQC/Ker1eCN6cthFWwpCEDqlHHkZMLjfKXKR\n" +
            "8zh+qWT0z6+t5T+8pk4zoZxK8DHJvfxsUpUy9Bie1u2xMJoRF7u1ifZ/lwYOtM6W\n" +
            "RwS4envPfA9djg2KOumX3Vnx/exPHudGDVCyCjwimpPtrLTJRnZyZGuMAECCxrXr\n" +
            "2hqzkzADrwKBgF2jBX6VotADA7l6yCWhO0kR3q6fpdyOin4ZmsubmJ1hwcs1yBI6\n" +
            "z+f34/muwDPUH7jCj9uTJqjqiBcPrlOm7641CYRUusZq0+HAR/LswNvXFrCABr3L\n" +
            "0E6RWKINNhBXvAE2BdFnuvO1FEuOJCObbY1LQUxjnWCiT9zRiUHX6SW9AoGAJife\n" +
            "vvoo0rMDmexPAtqsafJh9XY1IE3skVcjqpxzCy49GY+NhkEHkOSsBoUk2uix7okZ\n" +
            "QJ9aHrI1pU1XIxxCmjycV+E0E1FhfrtUJOJFvic8BedpqnKR138WCegt96jqbqAP\n" +
            "wEmssRd7eVAkkZwf3jtPABW4yqGRBC93buptBf8CgYEAs1yb4KSacp5/B9xsmb80\n" +
            "h8dr/l4pXaEVum2LbaRzaLSI1vttF9du0NuiyQ3OXeMA4mZUYGxalOfLi4f2tzAX\n" +
            "Kwcjmej8vjf1cMUas+6OXR9TUsBAhCqWJPnCP78T1Zi2vWKwfbO53krNvs/vVpy/\n" +
            "TapXUQew42pHEXwt0W5UkCQ=\n" +
            "-----END PRIVATE KEY-----\n";

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
