#!/bin/sh

# important:
# this script pulls and tests the most recent DNS resolvers, but none
# should be considered reliable unless thoroughly verified

(hash nslookup && hash curl) 2>/dev/null
if [ ! $? -eq 0 ]; then
	echo "required tools: nslookup, curl"
	exit
fi

RESOLVERS=$(curl -s 'https://public-dns.info/nameservers.csv' | \
grep ",true,1\.00,$(date +%Y-%m-%d)" | \
cut -d, -f1)

for res in $RESOLVERS; do
	nslookup -timeout=1 -retry=1 example.com $res >/dev/null
	if [ $? -eq 0 ]; then
		echo $res
	fi
done
