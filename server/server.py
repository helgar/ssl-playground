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
        print cert.get_subject()
        print errnum
        print errdepth
        print ok
        return True

    def __init__(self, server_address, HandlerClass, server_cert, ca_cert, server_key):
        print("self.address_family: %s" % self.address_family)
        self.address_family = socket.AF_INET
        print("self.socket_type: %s" % self.socket_type)
        self.socket_type = socket.SOCK_STREAM 
        BaseServer.__init__(self, server_address, HandlerClass)

        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
        ctx.set_options(OpenSSL.SSL.OP_NO_SSLv2)

        if not server_cert:
          raise Exception("No server cert!")

        # load server certificate
        cert_fd = open(server_cert, "r")
        cert_content = cert_fd.read(-1)
        cert_fd.close()

        certificate = OpenSSL.crypto.load_certificate(
          OpenSSL.crypto.FILETYPE_PEM, cert_content)

        ctx.use_certificate(certificate)

        # load server private key

        key_fd = open(server_key, "r")
        key_content = key_fd.read(-1)
        key_fd.close()
        key = OpenSSL.crypto.load_privatekey(
          OpenSSL.crypto.FILETYPE_PEM, key_content)

        ctx.use_privatekey(key)
        ctx.check_privatekey()

        # load ca cert
        ca_fd = open(ca_cert, "r")
        ca_cert_content = ca_fd.read(-1)
        ca_fd.close()

        ca_certificate = OpenSSL.crypto.load_certificate(
          OpenSSL.crypto.FILETYPE_PEM, ca_cert_content)

        try:
          # This will fail for PyOpenssl versions before 0.10
          ctx.add_client_ca(ca_certificate)
        except AttributeError:
          # Fall back to letting OpenSSL read the certificate file directly.
          ctx.load_client_ca(ca_cert)

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
         server_name=None,
         ca_cert=None,
         server_key=None):
    if not server_name:
      raise Exception("No server name given!")
    if not ca_cert:
      raise Exception("No CA cert was given!")
    if not server_key:
      raise Exception("No server key was given!")
    server_address = (server_name, 443) # (address, port)
    httpd = ServerClass(server_address, HandlerClass, server_cert, ca_cert, server_key)
    sa = httpd.socket.getsockname()
    print "Serving HTTPS on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()


if __name__ == '__main__':
  if len(sys.argv) < 5:
    print "Not enough arguments. Usage: ./server.py /path/to/server.pem server_name /path/to/ca/cert /path/to/serverprivatekey.pem"
  else:
    server_cert = sys.argv[1]
    server_name = sys.argv[2]
    ca_cert = sys.argv[3]
    server_key = sys.argv[4]
    print "Using server certificate: %s" % server_cert
    print "Using server address: %s" % server_name
    print "Using ca certificate: %s" % ca_cert
    print "Using server private key: %s" % server_key
    test(server_cert=server_cert, server_name=server_name, ca_cert=ca_cert, server_key=server_key)
