#!/bin/bash
TOKEN=$(awk '{ print $2 }' /mnt/integration_test/myagent.token)
spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf &
