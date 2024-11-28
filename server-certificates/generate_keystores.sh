#!/bin/bash

# Set default password
PASSWORD="123456"

# Step 1: Create server PKCS12 keystore from server certificate and private key
openssl pkcs12 -export -in server-cert.pem -inkey server-key.pem -name server -out server-keystore.p12 -CAfile ca-cert.pem -caname root -passout pass:$PASSWORD

# Step 2: Convert server PKCS12 keystore to JKS format
keytool -importkeystore -srckeystore server-keystore.p12 -srcstoretype PKCS12 -destkeystore server-keystore.jks -deststoretype JKS -srcstorepass $PASSWORD -deststorepass $PASSWORD

# Step 3: Convert server JKS keystore back to PKCS12 format (optional)
keytool -importkeystore -srckeystore server-keystore.jks -destkeystore server-keystore.jks -deststoretype PKCS12 -srcstorepass $PASSWORD -deststorepass $PASSWORD

# Step 4: Import CA certificate into a new truststore
keytool -import -trustcacerts -alias ca -file ca-cert.pem -keystore truststore.jks -storepass $PASSWORD -noprompt

# Step 5: Create client PKCS12 keystore from client certificate and private key
openssl pkcs12 -export -in client-cert.pem -inkey client-key.pem -name client -out client-keystore.p12 -CAfile ca-cert.pem -caname root -passout pass:$PASSWORD

# Step 6: Convert client PKCS12 keystore to JKS format
keytool -importkeystore -srckeystore client-keystore.p12 -srcstoretype PKCS12 -destkeystore client-keystore.jks -deststoretype JKS -srcstorepass $PASSWORD -deststorepass $PASSWORD

# Step 7: Convert client JKS keystore back to PKCS12 format (optional)
keytool -importkeystore -srckeystore client-keystore.jks -destkeystore client-keystore.jks -deststoretype PKCS12 -srcstorepass $PASSWORD -deststorepass $PASSWORD

# Step 8: Clean up .p12 and .old files
rm -f *.p12 *.old

echo "Keystore and truststore generation complete, and temporary files cleaned."