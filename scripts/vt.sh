#!/bin/bash

# VirusTotal API key is required

if [ $# -eq 0 ] || [ -z "$apikey" ]; then
	echo "usage: apikey=<apikey> $0 domain"
	exit
fi

(hash curl && hash jq) 2>/dev/null
if [ ! $? -eq 0 ]; then
	echo "required tools: curl, jq"
	exit
fi

curl -s "https://www.virustotal.com/api/v3/domains/$1/subdomains?limit=1000" -H "x-apikey: $apikey" | \
jq '.data[].id' | \
tr -d \" | \
sort -u
