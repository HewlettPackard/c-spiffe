#!/bin/bash
TOKEN=`awk '{ print $2 }' token`
echo $TOKEN
spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf &
