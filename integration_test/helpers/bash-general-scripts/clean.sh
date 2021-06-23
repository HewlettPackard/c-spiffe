rm -rf /mnt/c-spiffe/integration_test/data
rm -rf /mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/data
ssh root@workload "rm -rf /mnt/c-spiffe/integration_test/data && rm -rf /mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/data && rm -rf /mnt/c-spiffe/build/data"
ssh root@workload2 "rm -rf /mnt/c-spiffe/integration_test/data && rm -rf /mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/data && rm -rf /mnt/c-spiffe/build/data"
