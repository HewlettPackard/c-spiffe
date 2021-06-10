#!/usr/bin/env bash
echo -e '\n' | ssh-keygen -t rsa -P ''
cat /root/.ssh/id_rsa.pub > /mnt/c-spiffe/integration_test/helpers/bash-general-scripts/authorized_keys
