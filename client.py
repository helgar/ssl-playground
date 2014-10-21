#/usr/bin/python

# A very simple client to connect to a http(s) server

import pycurl
import utils

def _ConfigRpcCurl(curl, client_cert, ca_info, client_key):

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

  args = utils.parse_options()

  print("Using PycURL %s", pycurl.version)

  pycurl.global_init(pycurl.GLOBAL_ALL)

  res = Response()
  curl = pycurl.Curl()
  curl.setopt(curl.URL, "https://%s" % args.server_hostname)
  curl.setopt(curl.WRITEFUNCTION, res.callback)
  
  print ("Using client cert: %s" % args.client_cert)
  print ("Using ca cert: %s" % args.ca_cert)
  print ("Using client key: %s" % args.client_key)

  _ConfigRpcCurl(curl, args.client_cert, args.ca_cert, args.client_key)

  curl.perform()
  print res.content()

  pycurl.global_cleanup()

