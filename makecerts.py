#/usr/bin/python

import OpenSSL
import sys

X509_CERT_SIGN_DIGEST = "SHA1"
RSA_KEY_BITS = 2048

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
  if common_name:
    cert.get_subject().CN = common_name
  cert.set_serial_number(1)
  cert.gmtime_adj_notBefore(0)
  cert.gmtime_adj_notAfter(validity)
  cert.set_issuer(cert.get_subject())
  cert.set_pubkey(key)
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

if __name__ == "__main__":
  if len(sys.argv) < 5:
    print "Not enough arguments. Usage: ./makecerts.py cacert cakey clientcert clientkey"
  else:
    cacert = sys.argv[1]
    cakey = sys.argv[2]
    clientcert = sys.argv[3]
    clientkey = sys.argv[4]
    print ("cacert: %s\n cakey: %s\n clientcert: %s\n clientkey: %s\n" % (cacert, cakey, clientcert, clientkey))
    GenerateSelfSignedX509Cert("blablubb", 356, cacert, cakey)
