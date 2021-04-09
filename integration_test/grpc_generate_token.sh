#!/bin/bash
(spire-server token generate -spiffeID spiffe://example.org/myagent) > myagent.token &
