# A simple make file that runs the server and the client on localhost
# and offers to generate the certificates either with our python script
# or the openssl commandline tools.

run_client:
	python client.py

run_client_gnu:
	gnutls-cli -V --x509keyfile client_key.pem --x509certfile client_cert.pem --x509cafile ca_cert.pem localhost

run_client_openssl:
	openssl s_client -key client_key.pem -cert client_cert.pem -CAfile server_cert.pem -host magritte.muc.corp.google.com -port 9191 -tls1

run_server:
	python server.py

# make certs with our python script
certsp:
	python makecerts.py

# make self-signed certs with python script
certspss:
	python makecerts.py --server-sign-method=self

# make certs with open ssl commandline tools
certso:
	./makecerts_openssl.sh

clean:
	rm -rf *.pem serial* index*

show-server-cert:
	openssl x509 -in server_cert.pem -text

show-client-cert:
	openssl x509 -in client_cert.pem -text

verify-client-cert:
	openssl verify -CAfile /var/lib/ganeti/server.pem /var/lib/ganeti/client.pem
