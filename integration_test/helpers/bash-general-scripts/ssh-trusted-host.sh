#!/usr/bin/env bash
mkdir ~/.ssh
ssh -o "StrictHostKeyChecking no" workload << "EOL"
exit
EOL
ssh -o "StrictHostKeyChecking no" workload2 << "EOL"
exit
EOL
ssh -o "StrictHostKeyChecking no" spire-server2 << "EOL"
exit
EOL
