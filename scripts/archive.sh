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

curl --insecure -s "http://web.archive.org/cdx/search/cdx?url=$1&output=text&matchType=domain&fl=original&collapse=urlkey&limit=100000" | \
cut -d '/' -f 3 | \
egrep -o '^[a-z0-9.-]+[a-z]' | \
sort -u
