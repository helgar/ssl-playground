#/usr/bin/python

import argparse

SIGN_CA = 'ca'
SIGN_SELF = 'self'
SIGN_METHODS = {SIGN_CA, SIGN_SELF}

CA_CERT_FILE="ca_cert.pem"
CA_KEY_FILE="ca_key.pem"

CLIENT_CERT_FILE="client_cert.pem"
CLIENT_KEY_FILE="client_key.pem"
CLIENT_REQ_FILE="client_req.pem"

SERVER_CERT_FILE="server_cert.pem"
SERVER_KEY_FILE="server_key.pem"
SERVER_REQ_FILE="server_req.pem"

OPENSSL_CNF_FILE="openssl.cnf"

def parse_options():

  parser = argparse.ArgumentParser(description="Create SSL certificates")

  parser.add_argument('--openssl-conf', dest='openssl_conf',
                      metavar='openssl_conf',
                      action='store', default=OPENSSL_CNF_FILE,
                      help='Filename of the OpenSSL configuration file.')

  parser.add_argument('--ca-cert', dest='ca_cert', metavar='ca_cert',
                      action='store', default='ca_cert.pem',
                      help='Filename of CA certificate.')
  parser.add_argument('--ca-key', dest='ca_key', metavar='ca_key',
                      action='store', default=CA_KEY_FILE,
                      help='Filename of CA key.')
  parser.add_argument('--ca-create', dest='ca_create', action='store_true',
                      default=True,
                      help='Whether to create a new CA certificate/key pair.')

  parser.add_argument('--server-cert', dest='server_cert',
                      metavar='server_cert', action='store',
                      default=SERVER_CERT_FILE,
                      help='Filename of server certificate.')
  parser.add_argument('--server-key', dest='server_key',
                      metavar='server_key', action='store',
                      default=SERVER_KEY_FILE,
                      help='Filename of server key.')
  parser.add_argument('--server-req', dest='server_req',
                      metavar='server_req', action='store',
                      default=SERVER_REQ_FILE,
                      help='Filename of the server certificate signing '
                           'request.')
  parser.add_argument('--server-sign-method', dest='server_sign_method',
                      action='store', default=SIGN_CA, choices=SIGN_METHODS,
                      help='Method for signing the server certificate.')
  parser.add_argument('--server-create', dest='server_create',
                      action='store_true',
                      default=True,
                      help='Whether to create a new server certificate/key '
                           'pair.')

  parser.add_argument('--client-cert', dest='client_cert',
                      metavar='client_cert', action='store',
                      default=CLIENT_CERT_FILE,
                      help='Filename of client certificate.')
  parser.add_argument('--client-key', dest='client_key',
                      metavar='client_key', action='store',
                      default=CLIENT_KEY_FILE,
                      help='Filename of client key.')
  parser.add_argument('--client-req', dest='client_req',
                      metavar='client_req', action='store',
                      default=CLIENT_REQ_FILE,
                      help='Filename of client certificate signing request.')
  parser.add_argument('--client-sign-method', dest='client_sign_method',
                      action='store', default=SIGN_CA,
                      help='Method for signing the client certificate.')
  parser.add_argument('--client-create', dest='client_create',
                      action='store_true',
                      default=True,
                      help='Whether to create a new client certificate/key '
                           'pair.')

  args = parser.parse_args()

  print("openssl conf: %s" % args.openssl_conf)

  print("ca cert: %s" % args.ca_cert)
  print("ca key: %s" % args.ca_key)
  print("ca create: %s" % args.ca_create)

  print("server cert: %s" % args.server_cert)
  print("server key: %s" % args.server_key)
  print("server req: %s" % args.server_req)
  print("server signing method: %s" % args.server_sign_method)
  print("server create: %s" % args.server_create)

  print("client cert: %s" % args.client_cert)
  print("client key: %s" % args.client_key)
  print("client req: %s" % args.client_req)
  print("client signing method: %s" % args.client_sign_method)
  print("client create: %s" % args.client_create)

  return args

if __name__ == "__main__":
  pass
