#!/bin/bash

#token and agent
echo ./spire-server token generate -spiffeID spiffe://example.org/myagent 
spire-server token generate -spiffeID spiffe://example.org/myagent
echo "copie o token"
read TOKEN
echo ./spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf
spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf
