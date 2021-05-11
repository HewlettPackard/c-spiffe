#!/bin/bash
if [ $2 ];
then 
PREFIX=$2
else
PREFIX="my"
fi
TOKEN=$(awk '{ print $2 }' /mnt/c-spiffe/integration_test/${PREFIX}agent$1.token)
spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf &
