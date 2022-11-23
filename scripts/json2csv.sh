#!/bin/bash

(hash jq) 2>/dev/null
if [ ! $? -eq 0 ]; then
	echo "jq is required"
	exit
fi

jq -r '["domain", "a", "cname", "servfail", "refused"], (.[] | [.domain, .a[0], .cname[-1], .servfail, .refused]) | @csv' < "${1:-/dev/stdin}"
