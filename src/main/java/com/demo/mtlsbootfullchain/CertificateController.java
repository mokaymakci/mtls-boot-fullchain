package com.demo.mtlsbootfullchain;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletRequest;
import java.security.cert.X509Certificate;

@RestController
public class CertificateController {

    private final CertificateService certificateService;

    public CertificateController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @PostMapping("/generate_ca")
    public ResponseEntity<String> generateCACertificate() {
        certificateService.generateCACertificate();
        return ResponseEntity.ok("CA Certificate and Private Key generated successfully.");
    }

    @PostMapping("/generate_server")
    public ResponseEntity<String> generateServerCertificate() {
        certificateService.generateServerCertificate();
        return ResponseEntity.ok("Server Certificate and Private Key generated successfully.");
    }

    @GetMapping("/getCertificateData")
    public ResponseEntity<ClientCertficiateData> getCertificateData() throws Exception {
        ClientCertficiateData clientCertData = null;
        try {
            clientCertData = certificateService.generateClientCertificate();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return ResponseEntity.ok(clientCertData);
    }

    @GetMapping("/check")
    public String check(ServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        if (certs == null || certs.length == 0) {
            return "No certificate";
        }
        return certs[0].getIssuerX500Principal().getName();
    }

    @GetMapping("/ping")
    public String ping() {
        return "Pong!?!";
    }
}
