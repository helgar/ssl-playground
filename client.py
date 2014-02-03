#/usr/bin/python

# A very simple client to connect to a http(s) server

import pycurl
import sys
import OpenSSL

def _ConfigRpcCurl(curl, client_cert, ca_info, client_key):

  # reading CA info
  ca_fd = open(ca_info, "r")
  ca = "".join(ca_fd.readlines())
  ca_fd.close()
  print ca

  # reading client cert
  cert_fd = open(client_cert, "r")
  cert_content = cert_fd.read(-1)
  cert_fd.close()

  certificate = OpenSSL.crypto.load_certificate(
    OpenSSL.crypto.FILETYPE_PEM, cert_content)

  # reading client key
  key_fd = open(client_key, "r")
  key_content = key_fd.read(-1)
  key_fd.close()

  key = OpenSSL.crypto.load_privatekey(
    OpenSSL.crypto.FILETYPE_PEM, key_content)

  curl.setopt(pycurl.FOLLOWLOCATION, False)
  curl.setopt(pycurl.CAINFO, ca_info)
  curl.setopt(pycurl.SSL_VERIFYHOST, 0)
  curl.setopt(pycurl.SSL_VERIFYPEER, 1)
  curl.setopt(pycurl.SSLCERTTYPE, "PEM")
  curl.setopt(pycurl.SSLCERT, client_cert)
  curl.setopt(pycurl.SSLKEYTYPE, "PEM")
  curl.setopt(pycurl.SSLKEY, client_key)
  curl.setopt(pycurl.CONNECTTIMEOUT, 360)
  curl.setopt(pycurl.VERBOSE, 1)
  curl.setopt(pycurl.SSLVERSION, pycurl.SSLVERSION_SSLv3)


class Response(object):

  def __init__(self):
    self.chunks = []
  
  def callback(self, chunk):
    self.chunks.append(chunk)

  def content(self):
    return ''.join(self.chunks)


if __name__ == "__main__":
  print "I am a client!"
  if len(sys.argv) < 5:
    print "Not enough arguments. Usage: ./client.py client_cert server_address /path/to/cainfo client_key"
  else:
    client_cert = sys.argv[1]
    server_address = sys.argv[2]
    ca_info = sys.argv[3]
    client_key = sys.argv[4]
    print "Using client certificate: %s" % client_cert
    print "Contacting server address: %s" % server_address
    print "Using CA info: %s" % ca_info
    print "Using client key: %s" % client_key

    print("Using PycURL %s", pycurl.version)

    pycurl.global_init(pycurl.GLOBAL_ALL)

    res = Response()
    curl = pycurl.Curl()
    curl.setopt(curl.URL, server_address)
    curl.setopt(curl.WRITEFUNCTION, res.callback)
    
    _ConfigRpcCurl(curl, client_cert, ca_info, client_key)

    curl.perform()
    print res.content()

    pycurl.global_cleanup()

