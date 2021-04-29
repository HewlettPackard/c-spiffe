#!/bin/bash
(spire-server token generate -spiffeID spiffe://example.org/myagent) > /mnt/integration_test/myagent.token &
