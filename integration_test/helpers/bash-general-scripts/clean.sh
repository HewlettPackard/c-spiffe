rm -rf /mnt/c-spiffe/integration_test/data
rm -rf /mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/data
ssh root@workload "rm -rf /mnt/c-spiffe/integration_test/data && rm -rf /mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/data"
