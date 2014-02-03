#/usr/bin/python

# Very simple HTTP server for test purposes

import socket
from SocketServer import BaseServer
from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import OpenSSL

import utils

# create server.pem with
# openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes

class SecureHTTPServer(HTTPServer):

    def _SSLVerifyCallback(self, conn, cert, errnum, errdepth, ok):
        print "conn: %s" % conn
        print "cert: %s" % cert
        print "cert.subject: %s" % cert.get_subject()
        print "errnum: %s" % errnum
        print "errdepth: %s" % errdepth
        print "ok: %s" % ok
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

        certificate = utils.ReadCertificate(server_cert)
        ctx.use_certificate(certificate)

        key = utils.ReadKey(server_key)
        ctx.use_privatekey(key)
        ctx.check_privatekey()

        ca_certificate = utils.ReadCertificate(ca_cert)

        try:
          # This will fail for PyOpenssl versions before 0.10
          ctx.add_client_ca(ca_certificate)
        except AttributeError:
          # Fall back to letting OpenSSL read the certificate file directly.
          ctx.load_client_ca(ca_cert)

        print "Using server certificate: %s" % server_cert
        print "Using server address: %s" % str(server_address)
        print "Using ca certificate: %s" % ca_cert
        print "Using server private key: %s" % server_key

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

  args = utils.parse_options()

  test(server_cert=args.server_cert,
       server_name=args.server_hostname,
       ca_cert=args.ca_cert,
       server_key=args.server_key)
