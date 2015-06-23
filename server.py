#!/usr/bin/python

# Very simple HTTP server for test purposes

import socket
from SocketServer import BaseServer
from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import OpenSSL

import utils

class SecureHTTPServer(HTTPServer):

    def _SSLVerifyCallback(self, conn, cert, errnum, errdepth, ok):
        print "VERIFY PEER"
        print "conn: %s" % conn
        print "cert: %s" % cert
        print "cert.subject: %s" % cert.get_subject()
        print "errnum: %s" % errnum
        print "errdepth: %s" % errdepth
        print "ok: %s" % ok
        print "END VERIFY PEER"
        return True

    def __init__(self, server_address, HandlerClass, server_cert, ca_cert,
                 server_key, load_client_as_ca=False, client_cert=None,
                 ssl_verify_peer=True):
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

        if load_client_as_ca:
          ca_subject = ca_certificate.get_subject()
          print "Loading client cert: %s" % client_cert
          client_cert = utils.ReadCertificate(client_cert)
          client_subject = client_cert.get_subject()
          ca_list = [ca_subject, client_subject]
          ctx.set_client_ca_list(ca_list)
        else:
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


if __name__ == '__main__':

  args = utils.parse_options()

  HandlerClass=SecureHTTPRequestHandler
  ServerClass=SecureHTTPServer
  server_address = (args.server_hostname_start, int(args.server_port)) # (address, port)
  httpd = ServerClass(server_address, HandlerClass, args.server_cert,
                      args.ca_cert, args.server_key, args.load_client_ca,
                      args.client_cert)
  sa = httpd.socket.getsockname()
  print "Serving HTTPS on", sa[0], "port", sa[1], "..."
  httpd.serve_forever()
