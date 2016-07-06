#!/bin/bash

days=1000
if [ $# -eq 1 ]; then
	days=$1
fi

openssl req -x509 -newkey rsa:2048 -nodes -keyout slim-key.pem -out slim-cert.pem -days $days
cat slim-cert.pem slim-key.pem > slim-combined.pem

read -p "Move combined cert to /ets/ssl/certs? [Y/n]" response
response=${response:-Y}
if [ "Y$response" = "YY" ]; then
	sudo mv ./slim-combined.pem /etc/ssl/certs/

	read -p "Remove intermediate certificate files? [Y/n]" response
	response=${response:-Y}
	if [ "Y$response" = "YY" ]; then
		rm slim-cert.pem slim-key.pem
	fi
fi
