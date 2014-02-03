#/usr/bin/python

import OpenSSL
import os
import sys
import subprocess
import random
import argparse

SIGN_CA = 'ca'
SIGN_SELF = 'self'
SIGN_METHODS = {SIGN_CA, SIGN_SELF}

# TODO make proper makefile

X509_CERT_SIGN_DIGEST = "SHA1"
RSA_KEY_BITS = 2048

CA_CERT_FILE="ca_cert.pem"
CA_KEY_FILE="ca_key.pem"

CLIENT_CERT_FILE="client_cert.pem"
CLIENT_KEY_FILE="client_key.pem"
CLIENT_REQ_FILE="client_req.pem"

SERVER_CERT_FILE="server_cert.pem"
SERVER_KEY_FILE="server_key.pem"
SERVER_REQ_FILE="server_req.pem"

OPENSSL_CNF_FILE="openssl.cnf"

def SetSubject(subject):
  """
  Our default CA issuer name.
  """
  subject.CN = "Example CA"
  subject.ST = 'Viriginia'
  subject.C = "US"
  subject.emailAddress = 'ca@exampleca.org'
  subject.O = 'Root Certification Authority'

def SetServerSubject(subject):
  """
  Our default CA issuer name.
  """
  subject.CN = "localhost"
  subject.ST = 'Viriginia'
  subject.C = "US"
  subject.emailAddress = 'ca@exampleca.org'
  subject.O = 'Root Certification Authority'

def RunCmd(cmd, env=None):
  if not isinstance(cmd, basestring):
    cmd = [str(val) for val in cmd] 
  #cmd = ["openssl version -a"]
  print("Running command: %s" % ' '.join(cmd))
  cmd_str = ' '.join(cmd)

  p = subprocess.Popen(cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  out, err = p.communicate()
  print("RunCmd: OUT: %s\n ERR:%s\n" % (out, err)) 

## create root cert:
#OPENSSL_CONF=${CONFIG_FILE} openssl req -x509 -newkey rsa:2048 -out ${CA_CERT} -outform PEM -key ${PRIVATE_DIR}/${CA_KEY} -nodes
#
## check what it looks like:
#OPENSSL_CONF=${CONFIG_FILE} openssl x509 -in ${CA_CERT} -text -noout
#
## create a certificate request:
#unset OPENSSL_CONF && openssl req -newkey rsa:2048 -keyout ${SERVER_KEY} -keyform PEM -out ${SERVER_REQ} -nodes
#unset OPENSSL_CONF && openssl req -newkey rsa:2048 -keyout ${CLIENT_KEY} -keyform PEM -out ${CLIENT_REQ} -nodes
## check that it worked
#openssl req -in ${SERVER_REQ} -text -noout
#
## signing the certificate request with the CA
#OPENSSL_CONF=${CONFIG_FILE} openssl ca -in ${SERVER_REQ} -out ${SERVER_CERT} -md sha1
#OPENSSL_CONF=${CONFIG_FILE} openssl ca -in ${CLIENT_REQ} -out ${CLIENT_CERT} -md sha1
## consider using the -out and -notext option

def GetCaCertCmd(openssl_cnf_file, ca_cert_file, ca_key_file):
  return ["OPENSSL_CONF=%s" % openssl_cnf_file,
          'openssl', 'req', '-x509', '-newkey rsa:2048',
          '-out %s' % ca_cert_file,
          '-outform PEM',
          '-nodes']  

def GenerateCaCert(openssl_cnf_file, ca_cert_file, ca_key_file):
  cmd = GetCaCertCmd(openssl_cnf_file, ca_cert_file, ca_key_file)
  my_env = os.environ
  my_env["OPENSSL_CONF"] = openssl_cnf_file
  #cmd = "echo $OPENSSL_CONF"
  RunCmd(cmd, env=my_env)

def WritePemFile(pem_str, pem_file):
  pfd = open(pem_file, 'w')
  pfd.write(pem_str)
  pfd.close()

# TODO: refactor this to make it smarter

def WriteCertificate(cert, pem_file):
  pem_str = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
  WritePemFile(pem_str, pem_file)

def WriteKey(key, pem_file):
  pem_str = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
  WritePemFile(pem_str, pem_file)

def WriteRequest(req, pem_file):
  pem_str = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)
  WritePemFile(pem_str, pem_file)

def ReadPemFile(pem_file):
  pem_fd = open(pem_file, "r")
  pem_str = pem_fd.read(-1)
  pem_fd.close()
  return pem_str

def ReadCertificate(pem_file):
  pem_str = ReadPemFile(pem_file)
  cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_str)
  return cert

def ReadKey(pem_file):
  pem_str = ReadPemFile(pem_file)
  key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pem_str)
  return key

def ReadRequest(pem_file):
  pem_str = ReadPemFile(pem_file)
  key = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, pem_str)
  return key

def GenerateSelfSignedX509Cert(common_name, validity, certfile, keyfile):
  """Generates a self-signed X509 certificate.

  @type common_name: string
  @param common_name: commonName value
  @type validity: int
  @param validity: Validity for certificate in seconds
  @return: a tuple of strings containing the PEM-encoded private key and
           certificate

  """
  # Create private and public key
  key = OpenSSL.crypto.PKey()
  key.generate_key(OpenSSL.crypto.TYPE_RSA, RSA_KEY_BITS)

  # Create self-signed certificate
  cert = OpenSSL.crypto.X509()
  SetSubject(cert.get_subject())
  cert.set_serial_number(int(random.randrange(0,10001,2)))
  cert.gmtime_adj_notBefore(0)
  cert.gmtime_adj_notAfter(24 * 60 * 60 * 365)
  cert.set_issuer(cert.get_subject())
  cert.set_pubkey(key)
  cert.set_version(0x02)
  cert.add_extensions([
    OpenSSL.crypto.X509Extension("basicConstraints", False,
                                 "CA:TRUE"),
    ])

  cert.sign(key, X509_CERT_SIGN_DIGEST)

  WriteKey(key, keyfile)
  WriteCertificate(cert, certfile)

  return (key, cert)

def VerifyKeyCert(key, cert):
  ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
  ctx.use_privatekey(key)
  ctx.use_certificate(cert)
  try:
    ctx.check_privatekey()
  except OpenSSL.SSL.Error:
    return False
  else:
    return True

def VerifyKeyCertFile(key_file, cert_file):
  key = ReadKey(key_file)
  cert = ReadCertificate(cert_file)
  result = VerifyKeyCert(key, cert)
  if result:
    print("Certificate %s matches key %s." % (cert_file, key_file))
  else:
    print("Certificate %s does NOT match key %s." % (cert_file, key_file))

def GenerateKeyAndRequest(cacertfile, cakeyfile, certfile, keyfile, reqfile):

  # Create private and public key
  key = OpenSSL.crypto.PKey()
  key.generate_key(OpenSSL.crypto.TYPE_RSA, RSA_KEY_BITS)
  
  req = OpenSSL.crypto.X509Req()
  SetServerSubject(req.get_subject())
  req.set_pubkey(key)
  req.sign(key, X509_CERT_SIGN_DIGEST)

  WriteKey(key, keyfile)
  WriteRequest(req, reqfile)

  ca_cert = ReadCertificate(cacertfile)
  ca_key = ReadKey(cakeyfile)

  cert = OpenSSL.crypto.X509()
  cert.set_subject(req.get_subject())
  cert.set_serial_number(int(random.randrange(0,10001,2)))
  cert.gmtime_adj_notBefore(0)
  cert.gmtime_adj_notAfter(24 * 60 * 60 * 365)
  cert.set_issuer(ca_cert.get_subject())
  cert.set_pubkey(req.get_pubkey())
  cert.set_version(0x02)
  cert.add_extensions([
    OpenSSL.crypto.X509Extension("basicConstraints", False,
                                 "CA:FALSE"),
    ])
  cert.sign(ca_key, X509_CERT_SIGN_DIGEST)

  WriteCertificate(cert, certfile)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Create SSL certificates")

    parser.add_argument('--openssl-conf', dest='openssl_conf',
                        metavar='openssl_conf',
                        action='store', default=OPENSSL_CNF_FILE,
                        help='Filename of the OpenSSL configuration file.')

    parser.add_argument('--ca-cert', dest='ca_cert', metavar='ca_cert',
                        action='store', default='ca_cert.pem',
                        help='Filename of CA certificate.')
    parser.add_argument('--ca-key', dest='ca_key', metavar='ca_key',
                        action='store', default=CA_KEY_FILE,
                        help='Filename of CA key.')
    parser.add_argument('--ca-create', dest='ca_create', action='store_true',
                        default=True,
                        help='Whether to create a new CA certificate/key pair.')

    parser.add_argument('--server-cert', dest='server_cert',
                        metavar='server_cert', action='store',
                        default=SERVER_CERT_FILE,
                        help='Filename of server certificate.')
    parser.add_argument('--server-key', dest='server_key',
                        metavar='server_key', action='store',
                        default=SERVER_KEY_FILE,
                        help='Filename of server key.')
    parser.add_argument('--server-req', dest='server_req',
                        metavar='server_req', action='store',
                        default=SERVER_REQ_FILE,
                        help='Filename of the server certificate signing '
                             'request.')
    parser.add_argument('--server-sign-method', dest='server_sign_method',
                        action='store', default=SIGN_CA, choices=SIGN_METHODS,
                        help='Method for signing the server certificate.')
    parser.add_argument('--server-create', dest='server_create',
                        action='store_true',
                        default=True,
                        help='Whether to create a new server certificate/key '
                             'pair.')

    parser.add_argument('--client-cert', dest='client_cert',
                        metavar='client_cert', action='store',
                        default=CLIENT_CERT_FILE,
                        help='Filename of client certificate.')
    parser.add_argument('--client-key', dest='client_key',
                        metavar='client_key', action='store',
                        default=CLIENT_KEY_FILE,
                        help='Filename of client key.')
    parser.add_argument('--client-req', dest='client_req',
                        metavar='client_req', action='store',
                        default=CLIENT_REQ_FILE,
                        help='Filename of client certificate signing request.')
    parser.add_argument('--client-sign-method', dest='client_sign_method',
                        action='store', default=SIGN_CA,
                        help='Method for signing the client certificate.')
    parser.add_argument('--client-create', dest='client_create',
                        action='store_true',
                        default=True,
                        help='Whether to create a new client certificate/key '
                             'pair.')

    args = parser.parse_args()

    print("openssl conf: %s" % args.openssl_conf)

    print("ca cert: %s" % args.ca_cert)
    print("ca key: %s" % args.ca_key)
    print("ca create: %s" % args.ca_create)

    print("server cert: %s" % args.server_cert)
    print("server key: %s" % args.server_key)
    print("server req: %s" % args.server_req)
    print("server signing method: %s" % args.server_sign_method)
    print("server create: %s" % args.server_create)

    print("client cert: %s" % args.client_cert)
    print("client key: %s" % args.client_key)
    print("client req: %s" % args.client_req)
    print("client signing method: %s" % args.client_sign_method)
    print("client create: %s" % args.client_create)

    certs = [
      (args.server_create, args.server_sign_method,
       args.server_cert, args.server_key, args.server_req),
      (args.client_create, args.client_sign_method,
       args.client_cert, args.client_key, args.client_req),
            ]

    if args.ca_create:
      (cakeypem, cacertpem) = GenerateSelfSignedX509Cert(
        "localhost", 356, args.ca_cert, args.ca_key)
      VerifyKeyCertFile(args.ca_key, args.ca_cert)

    for (create, sign_method, cert, key, req) in certs:
      if create: 
        GenerateKeyAndRequest(args.ca_cert, args.ca_key, cert, key, req)
        VerifyKeyCertFile(key, cert)
