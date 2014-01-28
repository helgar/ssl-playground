#/usr/bin/python

# A very simple client to connect to a http(s) server

import pycurl
import sys

def _ConfigRpcCurl(curl, client_cert, ca_info):

  curl.setopt(pycurl.FOLLOWLOCATION, False)
  curl.setopt(pycurl.CAINFO, ca_info)
  curl.setopt(pycurl.SSL_VERIFYHOST, 0)
  curl.setopt(pycurl.SSL_VERIFYPEER, True)
  curl.setopt(pycurl.SSLCERTTYPE, "PEM")
  curl.setopt(pycurl.SSLCERT, client_cert)
  curl.setopt(pycurl.SSLKEYTYPE, "PEM")
  curl.setopt(pycurl.SSLKEY, client_cert)
  curl.setopt(pycurl.CONNECTTIMEOUT, 360)


class Response(object):

  def __init__(self):
    self.chunks = []
  
  def callback(self, chunk):
    self.chunks.append(chunk)

  def content(self):
    return ''.join(self.chunks)


if __name__ == "__main__":
  print "I am a client!"
  if len(sys.argv) < 3:
    print "Not enough arguments. Usage: ./client.py /path/to/client.pem server_address /path/to/cainfo"
  else:
    client_cert = sys.argv[1]
    server_address = sys.argv[2]
    ca_info = sys.argv[3]
    print "Using client certificate: %s" % client_cert
    print "Contacting server address: %s" % server_address
    print "Using CA info: %s" % ca_info

    res = Response()
    curl = pycurl.Curl()
    curl.setopt(curl.URL, server_address)
    curl.setopt(curl.WRITEFUNCTION, res.callback)
    
    _ConfigRpcCurl(curl, client_cert, ca_info)

    curl.perform()
    print res.content()

