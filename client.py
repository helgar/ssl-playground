#!/usr/bin/python

# A very simple client to connect to a http(s) server

import pycurl
import utils

def _ConfigRpcCurl(curl, client_cert, ca_info, client_key):

  curl.setopt(pycurl.VERBOSE, False)
  curl.setopt(pycurl.NOSIGNAL, True)
  curl.setopt(pycurl.USERAGENT, "Ganeti 12.15")
  curl.setopt(pycurl.PROXY, "")
#  curl.setopt(pycurl.CUSTOMREQUEST, "POST")
#  curl.setopt(pycurl.POSTFIELDS, "[]")
#  curl.setopt(pycurl.HTTPHEADER, ['Content-type: application/json', 'Expect:'])

  curl.setopt(pycurl.FOLLOWLOCATION, False)
  curl.setopt(pycurl.CAINFO, ca_info)
  curl.setopt(pycurl.SSL_VERIFYHOST, 0)
  curl.setopt(pycurl.SSL_VERIFYPEER, 1)
  curl.setopt(pycurl.SSLCERTTYPE, "PEM")
  curl.setopt(pycurl.SSLCERT, client_cert)
  curl.setopt(pycurl.SSLKEYTYPE, "PEM")
  curl.setopt(pycurl.SSLKEY, client_key)
  curl.setopt(pycurl.CONNECTTIMEOUT, 360)
  curl.setopt(pycurl.SSLVERSION, pycurl.SSLVERSION_SSLv3)

  curl.setopt(pycurl.TIMEOUT, 100)


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
  curl.setopt(curl.URL, "https://%s:%s" %
              (args.server_hostname, args.server_port))
  curl.setopt(curl.WRITEFUNCTION, res.callback)
  
  print ("Using client cert: %s" % args.client_cert)
  print ("Using ca cert: %s" % args.ca_cert)
  print ("Using client key: %s" % args.client_key)

  _ConfigRpcCurl(curl, args.client_cert, args.ca_cert, args.client_key)

  print "XXXXXXXXXXXXXXXXXXXXXXXXXX"
  print curl
  print dir(curl)
  print dir(pycurl)
  #print curl.getinfo(pycurl.INFO_CERTINFO)
  print "XXXXXXXXXXXXXXXXXXXXXXXXXX"

  curl.perform()
  print res.content()

  pycurl.global_cleanup()

