#!/usr/bin/env bash
#arguments: $1 = 'server' or 'agent'; $2 = hostname
ssh root@$2 "`env | sed 's/;/\\\\;/g' | sed 's/.*/set &\;/g'` pkill spire-'$1'"
