#!/usr/bin/env bash
#arguments: $1 = 'server' or 'agent'; $2 = hostname; $3 = workload_id (optional)
if [ $3 ];
then
TOKEN=$(awk '{ print $2 }' /mnt/c-spiffe/integration_test/myagent${3}.token)
ssh root@$2 "ps aux | grep spire-${1} | grep ${TOKEN} | awk '{ print \$2 }' | xargs -I {} kill -9 {}"
else
ssh root@$2 "pkill -9 spire-$1"
fi
