#/usr/bin/bash

SERIAL_FILE=serial
INDEX_FILE=index.txt

CA_CERT=cacert.pem
CA_KEY=cakey.pem

SERVER_REQ=server_req.pem
echo "SERVER_REQ ${SERVER_REQ}"
SERVER_KEY=server_key.pem
echo "SERVER_KEY ${SERVER_KEY}"
SERVER_CERT=server_cert.pem
echo "SERVER_CERT ${SERVER_CERT}"

CLIENT_REQ=client_req.pem
echo "CLIENT_REQ ${CLIENT_REQ}"
CLIENT_KEY=client_key.pem
echo "CLIENT_KEY ${CLIENT_KEY}"
CLIENT_CERT=client_cert.pem
echo "CLIENT_CERT ${CLIENT_CERT}"

CONFIG_FILE=$(pwd)/openssl.cnf
echo "CONFIG_FILE ${CONFIG_FILE}"
CERT_DIR=$(pwd)/certs
echo "CERT_DIR ${CERT_DIR}"
PRIVATE_DIR=$(pwd)/private
echo "PRIVATE_DIR ${PRIVATE_DIR}"

rm ${SERIAL_FILE}
echo '01' > ${SERIAL_FILE}
rm ${INDEX_FILE}
touch ${INDEX_FILE}
rm ${CERT_DIR}/*
mkdir -p ${CERT_DIR}
mkdir -p ${PRIVATE_DIR}

# create root cert:
OPENSSL_CONF=${CONFIG_FILE} openssl req -x509 -newkey rsa:2048 -out ${CA_CERT} -outform PEM -key ${PRIVATE_DIR}/${CA_KEY} -nodes

# check what it looks like:
OPENSSL_CONF=${CONFIG_FILE} openssl x509 -in ${CA_CERT} -text -noout

# create a certificate request:
unset OPENSSL_CONF && openssl req -newkey rsa:2048 -keyout ${SERVER_KEY} -keyform PEM -out ${SERVER_REQ} -nodes
unset OPENSSL_CONF && openssl req -newkey rsa:2048 -keyout ${CLIENT_KEY} -keyform PEM -out ${CLIENT_REQ} -nodes
# check that it worked
openssl req -in ${SERVER_REQ} -text -noout

# signing the certificate request with the CA
OPENSSL_CONF=${CONFIG_FILE} openssl ca -in ${SERVER_REQ} -out ${SERVER_CERT} -md sha1
OPENSSL_CONF=${CONFIG_FILE} openssl ca -in ${CLIENT_REQ} -out ${CLIENT_CERT} -md sha1
# consider using the -out and -notext option
