#!/usr/bin/env bash
mkdir ~/.ssh
ssh -o "StrictHostKeyChecking no" workload << "EOL"
exit
EOL