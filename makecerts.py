#/usr/bin/python

import OpenSSL
import os
import sys
import subprocess
import random

# TODO make proper makefile

X509_CERT_SIGN_DIGEST = "SHA1"
RSA_KEY_BITS = 2048

CA_CERT_FILE="ca_cert.pem"
CA_KEY_FILE="ca_key.pem"

#CA_CERT_CMD_FILE="ca_cert.pem"
#CA_KEY_CMD_FILE="ca_key.pem"

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
  VerifyKeyCert(key, cert)

  return (key, cert)

def VerifyKeyCert(key, cert):
  ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
  ctx.use_privatekey(key)
  ctx.use_certificate(cert)
  try:
    ctx.check_privatekey()
  except OpenSSL.SSL.Error:
    print "Incorrect key"
  else:
    print "Key matches certificate"

def VerifyKeyCertFile(key_file, cert_file):
  key = ReadKey(key_file)
  cert = ReadCertificate(cert_file)
  VerifyKeyCert(key, cert)

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
  VerifyKeyCert(key, cert)

if __name__ == "__main__":
  # TODO: parse options properly
  print "yay!"
  if len(sys.argv) < 6:
    print "Not enough arguments. Usage: ./makecerts.py cacert cakey clientcert clientkey clientreq openssl"
  else:
    cacert = sys.argv[1]
    cakey = sys.argv[2]
    clientcert = sys.argv[3]
    clientkey = sys.argv[4]
    clientreq = sys.argv[5]
    openssl_cnf = sys.argv[6]
    print ("cacert: %s\n cakey: %s\n clientcert: %s\n clientkey: %s\n clientreq: %s" % (cacert, cakey, clientcert, clientkey, clientreq))
    (cakeypem, cacertpem) = GenerateSelfSignedX509Cert("localhost", 356, CA_CERT_FILE, CA_KEY_FILE)
    VerifyKeyCertFile(CA_KEY_FILE, CA_CERT_FILE)
    (cakeypem, cacertpem) = GenerateSelfSignedX509Cert("localhost", 356, "other_ca_cert.pem", "other_ca_key.pem")
    VerifyKeyCertFile("other_ca_key.pem", "other_ca_cert.pem")
    #GenerateCaCert(openssl_cnf, CA_CERT_CMD_FILE, CA_KEY_CMD_FILE)
    #VerifyKeyCertFile(CA_KEY_CMD_FILE, CA_CERT_CMD_FILE)
    GenerateKeyAndRequest(CA_CERT_FILE, CA_KEY_FILE, CLIENT_CERT_FILE, CLIENT_KEY_FILE, CLIENT_REQ_FILE)
    GenerateKeyAndRequest(CA_CERT_FILE, CA_KEY_FILE, SERVER_CERT_FILE, SERVER_KEY_FILE, SERVER_REQ_FILE)
