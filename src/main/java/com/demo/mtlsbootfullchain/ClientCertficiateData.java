package com.demo.mtlsbootfullchain;

public class ClientCertficiateData {
    private String privateKey;
    private String certificate;

    public ClientCertficiateData(String certificate, String privateKey) {
        this.privateKey = privateKey;
        this.certificate = certificate;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }
}
