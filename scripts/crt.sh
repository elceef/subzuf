#!/bin/bash

if [ $# -eq 0 ]; then
	echo "usage: $0 domain"
	exit
fi

(hash curl && hash jq && hash sed) 2>/dev/null
if [ ! $? -eq 0 ]; then
	echo "required tools: curl, jq, sed"
	exit
fi

curl -s "https://crt.sh?q=%.$1&output=json" | \
jq -r '.[].common_name,.[].name_value' | \
tr -d \" | \
sed 's/\\n/\n/g' | \
egrep '^[a-zA-Z0-9.-]+$' | \
grep "\.$1$" | \
sort -u
