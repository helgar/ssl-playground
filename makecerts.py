#/usr/bin/python

import OpenSSL
import sys
import subprocess

X509_CERT_SIGN_DIGEST = "SHA1"
RSA_KEY_BITS = 2048

def SetSubject(subject):
  """
  Our default CA issuer name.
  """
  subject.C = "DE"
  subject.CN = "localhost"
  subject.ST = 'DE'
  subject.L = 'Munich'
  subject.O = 'Ganeti'
  subject.OU = 'Ganeti Testing'
  subject.emailAddress = 'ganeti@ganeti.org'

def RunCmd(cmd):
  if not isinstance(cmd, basestring):
    cmd = [str(val) for val in cmd] 

  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  out, err = p.communicate()
  print("RunCmd: OUT: %s\n ERR:%s\n" % (out, err)) 


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
  cert.set_serial_number(1)
  cert.gmtime_adj_notBefore(0)
  cert.gmtime_adj_notAfter(24 * 60 * 60 * 365)
  cert.set_issuer(cert.get_subject())
  cert.set_pubkey(key)
  cert.set_version(0x02)
  cert.add_extensions([
    OpenSSL.crypto.X509Extension("basicConstraints", True,
                                 "CA:TRUE, pathlen:0"),
    OpenSSL.crypto.X509Extension("keyUsage", True,
                                 "keyCertSign, cRLSign, digitalSignature, keyEncipherment"),
    OpenSSL.crypto.X509Extension("subjectKeyIdentifier", False, "hash",
                                 subject=cert),
    ])

  cert.sign(key, X509_CERT_SIGN_DIGEST)

  key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
  cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

  cfd = open(certfile, 'w')
  cfd.write(cert_pem)
  cfd.close()

  kfd = open(keyfile, 'w')
  kfd.write(key_pem)
  kfd.close()

  return (key, cert)


def GenerateKeyAndRequest(cacertfile, cakeyfile, certfile, keyfile, reqfile):

  # Create private and public key
  key = OpenSSL.crypto.PKey()
  key.generate_key(OpenSSL.crypto.TYPE_RSA, RSA_KEY_BITS)
  
  req = OpenSSL.crypto.X509Req()
  SetSubject(req.get_subject())
  req.set_pubkey(key)
  req.sign(key, X509_CERT_SIGN_DIGEST)

  # Write private key
  key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)

  # Write request
  req_pem = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)

  cfd = open(reqfile, 'w')
  cfd.write(req_pem)
  cfd.close()

  kfd = open(keyfile, 'w')
  kfd.write(key_pem)
  kfd.close()

  # load ca certificates
  cacert_fd = open(cacertfile, "r")
  cacert_content = cacert_fd.read(-1)
  cacert_fd.close()

  cakey_fd = open(cakeyfile, "r")
  cakey_content = cakey_fd.read(-1)
  cakey_fd.close()

  ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cacert_content)
  ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, cakey_content)

  cert = OpenSSL.crypto.X509()
  cert.set_subject(req.get_subject())
  cert.set_serial_number(1)
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

  cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

  cfd = open(certfile, 'w')
  cfd.write(cert_pem)
  cfd.close()

  ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
  ctx.use_privatekey(key)
  ctx.use_certificate(cert)
  try:
    ctx.check_privatekey()
  except OpenSSL.SSL.Error:
    print "Incorrect key"
  else:
    print "Key matches certificate"


  return (key_pem, cert_pem)



if __name__ == "__main__":
  if len(sys.argv) < 5:
    print "Not enough arguments. Usage: ./makecerts.py cacert cakey clientcert clientkey clientreq"
  else:
    cacert = sys.argv[1]
    cakey = sys.argv[2]
    clientcert = sys.argv[3]
    clientkey = sys.argv[4]
    clientreq = sys.argv[5]
    print ("cacert: %s\n cakey: %s\n clientcert: %s\n clientkey: %s\n clientreq: %s" % (cacert, cakey, clientcert, clientkey, clientreq))
    (cakeypem, cacertpem) = GenerateSelfSignedX509Cert("localhost", 356, cacert, cakey)
    GenerateKeyAndRequest(cacert, cakey, clientcert, clientkey, clientreq)
