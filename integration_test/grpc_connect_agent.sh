#!/bin/bash
TOKEN=$(awk '{ print $2 }' token.txt)
rm token.txt
spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf &
