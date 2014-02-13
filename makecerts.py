#/usr/bin/python

import OpenSSL
import os
import subprocess
import random
import utils

# TODO make proper makefile

X509_CERT_SIGN_DIGEST = "SHA1"
RSA_KEY_BITS = 2048
DEFAULT_VALIDITY_DAYS = 24 * 60 * 60 * 365 # one year

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
  cert.gmtime_adj_notAfter(DEFAULT_VALIDITY_DAYS)
  cert.set_issuer(cert.get_subject())
  cert.set_pubkey(key)
  cert.set_version(0x02)
  cert.add_extensions([
    OpenSSL.crypto.X509Extension("basicConstraints", False,
                                 "CA:TRUE"),
    ])

  cert.sign(key, X509_CERT_SIGN_DIGEST)

  utils.WriteKey(key, keyfile)
  utils.WriteCertificate(cert, certfile)

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
  key = utils.ReadKey(key_file)
  cert = utils.ReadCertificate(cert_file)
  result = VerifyKeyCert(key, cert)
  if result:
    print("Certificate %s matches key %s." % (cert_file, key_file))
  else:
    print("Certificate %s does NOT match key %s." % (cert_file, key_file))


def GenerateKeyAndRequest(cacertfile, cakeyfile, certfile, keyfile, reqfile):

  key = OpenSSL.crypto.PKey()
  key.generate_key(OpenSSL.crypto.TYPE_RSA, RSA_KEY_BITS)
  
  req = OpenSSL.crypto.X509Req()
  SetServerSubject(req.get_subject())
  req.set_pubkey(key)
  req.sign(key, X509_CERT_SIGN_DIGEST)

  utils.WriteKey(key, keyfile)
  utils.WriteRequest(req, reqfile)


def SignRequest(reqfile, cacertfile, cakeyfile, certfile):

  req = utils.ReadRequest(reqfile)

  ca_cert = utils.ReadCertificate(cacertfile)
  ca_key = utils.ReadKey(cakeyfile)

  cert = OpenSSL.crypto.X509()
  cert.set_subject(req.get_subject())
  cert.set_serial_number(int(random.randrange(0,10001,2)))
  cert.gmtime_adj_notBefore(0)
  cert.gmtime_adj_notAfter(DEFAULT_VALIDITY_DAYS)
  cert.set_issuer(ca_cert.get_subject())
  cert.set_pubkey(req.get_pubkey())
  cert.set_version(0x02)
  cert.add_extensions([
    OpenSSL.crypto.X509Extension("basicConstraints", False,
                                 "CA:FALSE"),
    ])
  cert.sign(ca_key, X509_CERT_SIGN_DIGEST)

  utils.WriteCertificate(cert, certfile)


if __name__ == "__main__":

  args = utils.parse_options()

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
      SignRequest(req, args.ca_cert, args.ca_key, cert)
      VerifyKeyCertFile(key, cert)
