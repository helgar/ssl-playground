#/usr/bin/bash

SERIAL_FILE=serial
INDEX_FILE=index.txt

CA_CERT=cacert.pem
CA_KEY=cakey.pem

CLIENT_REQ=testreq.pem
CLIENT_KEY=testkey.pem
CLIENT_CERT=testcert.pem

CONFIG_FILE=$(pwd)/openssl.cnf
CERT_DIR=$(pwd)/certs

rm ${SERIAL_FILE}
echo '01' > ${SERIAL_FILE}
rm ${INDEX_FILE}
touch ${INDEX_FILE}
rm ${CERT_DIR}/*

# create root cert:
OPENSSL_CONF=${CONFIG_FILE} openssl req -x509 -newkey rsa -out ${CA_CERT} -outform PEM -nodes

# check what it looks like:
OPENSSL_CONF=${CONFIG_FILE} openssl x509 -in ${CA_CERT} -text -noout

# create a certificate request:
# clear config file path first
unset OPENSSL_CONF && openssl req -newkey rsa:1024 -keyout ${CLIENT_KEY} -keyform PEM -out ${CLIENT_REQ} -nodes
# check that it worked
openssl req -in ${CLIENT_REQ} -text -noout

# signing the certificate request with the CA
OPENSSL_CONF=${CONFIG_FILE} openssl ca -in ${CLIENT_REQ}
# consider using the -out and -notext option
