#/usr/bin/python

# Very simple HTTP server for test purposes

import socket
import sys
from SocketServer import BaseServer
from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import OpenSSL

# create server.pem with
# openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes

class SecureHTTPServer(HTTPServer):

    def _SSLVerifyCallback(self, conn, cert, errnum, errdepth, ok):
        print conn
        print cert
        print errnum
        print errdepth
        print ok
        return True

    def __init__(self, server_address, HandlerClass, server_cert):
        print("self.address_family: %s" % self.address_family)
        self.address_family = socket.AF_INET
        print("self.socket_type: %s" % self.socket_type)
        self.socket_type = socket.SOCK_STREAM 
        BaseServer.__init__(self, server_address, HandlerClass)

        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        ctx.set_options(OpenSSL.SSL.OP_NO_SSLv2)

        if not server_cert:
          raise Exception("No server cert!")

        cert_fd = open(server_cert, "r")
        cert_content = cert_fd.read(-1)
        cert_fd.close()

        certificate = OpenSSL.crypto.load_certificate(
          OpenSSL.crypto.FILETYPE_PEM, cert_content)
        key = OpenSSL.crypto.load_privatekey(
          OpenSSL.crypto.FILETYPE_PEM, cert_content)

        ctx.use_privatekey(key)
        ctx.use_certificate(certificate)
        ctx.check_privatekey()

        ctx.set_verify(OpenSSL.SSL.VERIFY_PEER |
                       OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                       self._SSLVerifyCallback)

        self.socket = OpenSSL.SSL.Connection(
           ctx, socket.socket(self.address_family, self.socket_type))

        self.server_bind()
        self.server_activate()

    def shutdown(self, arg):
      try:
        super(BaseServer, self).shutdown(arg)
      except Exception:
        super(BaseServer, self).shutdown()


class SecureHTTPRequestHandler(SimpleHTTPRequestHandler):
    def setup(self):
        self.connection = self.request
        self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
        self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)


def test(HandlerClass=SecureHTTPRequestHandler,
         ServerClass=SecureHTTPServer,
         server_cert=None,
         server_name=None):
    if not server_name:
      raise Exception("No server name given!")
    server_address = (server_name, 443) # (address, port)
    httpd = ServerClass(server_address, HandlerClass, server_cert)
    sa = httpd.socket.getsockname()
    print "Serving HTTPS on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()


if __name__ == '__main__':
  if len(sys.argv) < 3:
    print "Not enough arguments. Usage: ./server.py /path/to/server.pem server_name"
  else:
    server_cert = sys.argv[1]
    server_name = sys.argv[2]
    print "Using server certificate: %s" % server_cert
    print "Using server address: %s" % server_name
    test(server_cert=server_cert, server_name=server_name)
