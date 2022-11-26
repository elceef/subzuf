#!/bin/bash

if [ $# -eq 0 ]; then
	echo "usage: $0 domain"
	exit
fi

(hash curl) 2>/dev/null
if [ ! $? -eq 0 ]; then
	echo "curl is required"
	exit
fi

curl -s "https://api.hackertarget.com/hostsearch/?q=$1" | \
cut -d, -f1
