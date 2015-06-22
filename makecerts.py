#!/usr/bin/python

import OpenSSL
import random
import utils


X509_CERT_SIGN_DIGEST = "SHA1"
RSA_KEY_BITS = 2048
DEFAULT_VALIDITY_DAYS = 24 * 60 * 60 * 365 # one year


def SetCaSubject(subject, common_name):
  """
  Our default CA issuer name.
  """
  subject.CN = common_name
  subject.ST = 'Viriginia'
  subject.C = "US"
  subject.emailAddress = 'ca@exampleca.org'
  subject.O = 'Root Certification Authority'


def SetSubject(subject, common_name):
  """
  Our default CA issuer name.
  """
  subject.CN = common_name
  subject.ST = 'Viriginia'
  subject.C = "US"
  subject.emailAddress = 'ca@exampleca.org'
  subject.O = 'Root Certification Authority'


def GenerateSelfSignedCert(common_name, certfile, keyfile):
  print "common name: %s" % common_name

  key = OpenSSL.crypto.PKey()
  key.generate_key(OpenSSL.crypto.TYPE_RSA, RSA_KEY_BITS)

  cert = OpenSSL.crypto.X509()
  SetCaSubject(cert.get_subject(), common_name)
  cert.set_serial_number(int(random.randrange(0,10001,2)))
  cert.gmtime_adj_notBefore(0)
  cert.gmtime_adj_notAfter(DEFAULT_VALIDITY_DAYS)
  cert.set_issuer(cert.get_subject())
  cert.set_pubkey(key)
  cert.set_version(0x02)
#  cert.add_extensions([
#    OpenSSL.crypto.X509Extension("basicConstraints", False,
#                                 "CA:TRUE"),
#    ])

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


def GenerateKeyAndRequest(cacertfile, cakeyfile, certfile, keyfile, reqfile, common_name):

  key = OpenSSL.crypto.PKey()
  key.generate_key(OpenSSL.crypto.TYPE_RSA, RSA_KEY_BITS)
  
  req = OpenSSL.crypto.X509Req()
  SetSubject(req.get_subject(), common_name)
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
     args.server_cert, args.server_key, args.server_req,
     args.server_hostname),
    (args.client_create, args.client_sign_method,
     args.client_cert, args.client_key, args.client_req,
     args.client_hostname),
          ]

  if args.ca_create:
    (cakeypem, cacertpem) = GenerateSelfSignedCert(
      args.ca_hostname, args.ca_cert, args.ca_key)
    VerifyKeyCertFile(args.ca_key, args.ca_cert)

  for (create, sign_method, cert, key, req, hostname) in certs:
    if create: 
      if sign_method == utils.SIGN_CA:
        print "Chose CA SIGNED"
        print "signing by %s %s" % (args.ca_cert, args.ca_key)
        GenerateKeyAndRequest(args.ca_cert, args.ca_key, cert, key, req,
                              hostname)
        SignRequest(req, args.ca_cert, args.ca_key, cert)
        VerifyKeyCertFile(key, cert)
      if sign_method == utils.SIGN_SELF:
        print "Chose SELF SIGNED"
        GenerateSelfSignedCert(hostname, cert, key)

