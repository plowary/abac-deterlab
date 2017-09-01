#!/bin/bash
# Script requires OpenSSL to be installed and the provided openssl.cnf and create_attr_cert.jar in same directory

set -e

# Set proper directory path for openssl.cnf
export REGR_PATH=$PWD

# Clean the directory (for testing)
testing=true
if ${testing}
then
    rm -rf ca
    rm -f *.pem *.der
    find -name '*.xml' ! -name '*_uns.xml' -delete # Delete the non-unsigned (auto-generated) XML files
fi

# Setup the read DER credential test using voodoo and other surreptitious methods
echo 'Setting up the read DER credential test...'
openssl req -batch -nodes -x509 -newkey rsa:1024 -keyout Acme-check-x509.key.pem -out Acme-check-x509.pem -days 3650 -subj '/CN=Acme'
## Get the UUID we'll use to generate the certificates and store it
der_uuid=$(openssl x509 -in Acme-check-x509.pem -noout -text | sed -n '/Subject Key Identifier/{n;p;}' | python3 -c "import sys;print(sys.stdin.readline().strip().lower().replace(\":\", \"\"));")
rm Acme-check-x509.key.pem Acme-check-x509.pem
# Generate e0-check-x509.der and Acme-check-x509.pem
java -jar create_attr_cert.jar

# Generate not_ss.pem and the associated CA for read not_ss.xml credential test
# Tutorial at jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html
echo 'Setting up the read not-self-signed credential test...'
rm -rf ./ca
mkdir ./ca
cd ./ca
mkdir certs crl csr newcerts private
touch index.txt
echo 01\n > serial
openssl genrsa -out private/ca.key.pem 1024
openssl req -batch -nodes -config ../openssl.cnf -key private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.cert.pem -subj '/C=US/ST=California/O=USC ISI/OU=Certificate Authority/CN=isi.deterlab.net'
openssl genrsa -out private/not_ss.key.pem 1024
openssl req -batch -config ../openssl.cnf -key private/not_ss.key.pem -new -out csr/not_ss.csr.pem -subj '/C=US/ST=California/O=USC ISI/OU=DETER Team/CN=abac.deterlab.net'
openssl ca -batch -config ../openssl.cnf -extensions usr_cert -days 3650 -notext -md sha256 -in csr/not_ss.csr.pem -out certs/not_ss.pem
cp certs/not_ss.pem ..
cp private/not_ss.key.pem ..
cd ..

# Generate Acme-check-geni.pem for read GENI v1.0 credentials test (deprecated)
echo 'Setting up the read GENI v1.0 credential test...'
openssl req -batch -nodes -x509 -newkey rsa:1024 -keyout Acme-check-geni.key.pem -out Acme-check-geni.pem -days 3650 -subj '/CN=Acme'

# Generate Acme-check-geni11.pem for read GENI v1.1 credentials test
echo 'Setting up the read GENI v1.1 credential test...'
openssl req -batch -nodes -x509 -newkey rsa:1024 -keyout Acme-check-geni11.key.pem -out Acme-check-geni11.pem -days 3650 -subj '/CN=Acme'

# Generate issuer.pem for read priv.xml credential test
echo 'Setting up the read priv credential test...'
openssl req -batch -nodes -x509 -newkey rsa:1024 -keyout issuer.key.pem -out issuer.pem -days 3650 -subj '/CN=issuer'

# Set the principal GUIDs in the unsigned XML files to the GUIDs of the subjects of the certs
echo 'Updating the GUIDs in the unsigned XML files...'
python3 ./update_xml.py e0-check-geni_uns.xml Acme-check-geni.pem
python3 ./update_xml.py e0-check-geni11_uns.xml Acme-check-geni11.pem
python3 ./update_xml.py priv_uns.xml issuer.pem
python3 ./update_xml.py not_ss_uns.xml not_ss.pem

# Sign and output the XML files with the generated certs
echo 'Signing the XML files...'
xmlsec1 --sign --privkey-pem Acme-check-geni.key.pem,Acme-check-geni.pem --output e0-check-geni.xml e0-check-geni_uns.xml
xmlsec1 --sign --privkey-pem Acme-check-geni11.key.pem,Acme-check-geni11.pem --output e0-check-geni11.xml e0-check-geni11_uns.xml
xmlsec1 --sign --privkey-pem issuer.key.pem,issuer.pem --output priv.xml priv_uns.xml
xmlsec1 --sign --privkey-pem not_ss.key.pem,not_ss.pem --output not_ss.xml not_ss_uns.xml

# Clean up
rm -rf ca
unset REGR_PATH
unset DER_UUID