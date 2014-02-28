# A simple make file that runs the server and the client on localhost
# and offers to generate the certificates either with our python script
# or the openssl commandline tools.

run_client:
	python client.py

run_server:
	python server.py

# make certs with our python script
certsp:
	python makecerts.py

# make certs with open ssl commandline tools
certso:
	./makecerts_openssl.sh

clean:
	rm -rf *.pem serial* index*
