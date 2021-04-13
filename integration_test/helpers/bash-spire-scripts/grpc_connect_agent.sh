#!/bin/bash
TOKEN=$(awk '{ print $2 }' /mnt/c-spiffe/integration_test/myagent.token)
spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf &
