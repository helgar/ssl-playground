#/usr/bin/bash

OPENSSL_CONF=$(pwd)/openssl.cnf
echo "Exporting openssl config file ${OPENSSL_CONF}."
export OPENSSL_CONF

# create root cert:
OPENSSL_CONF=$(pwd)/openssl.cnf openssl req -x509 -newkey rsa -out cacert.pem -outform PEM -nodes

# check what it looks like:
OPENSSL_CONF=$(pwd)/openssl.cnf openssl x509 -in cacert.pem -text -noout

# create a certificate request:
# clear config file path first
unset OPENSSL_CONF && openssl req -newkey rsa:1024 -keyout testkey.pem -keyform PEM -out testreq.pem -nodes
# check that it worked
openssl req -in testreq.pem -text -noout

# signing the certificate request with the CA
OPENSSL_CONF=$(pwd)/openssl.cnf openssl ca -in testreq.pem
# consider using the -out and -notext option
