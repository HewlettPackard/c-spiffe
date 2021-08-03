#!/usr/bin/env bash
# (C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP
#
# 
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# 
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# 
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

#arguments: $1 = 'server' (optional)
rm -rf /mnt/c-spiffe/integration_test/data
rm -rf /mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/data
ssh root@workload "rm -rf /mnt/c-spiffe/integration_test/data && rm -rf /mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/data && rm -rf /mnt/c-spiffe/build/data"
ssh root@workload2 "rm -rf /mnt/c-spiffe/integration_test/data && rm -rf /mnt/c-spiffe/integration_test/helpers/bash-spire-scripts/data && rm -rf /mnt/c-spiffe/build/data"
if [ $1 ];
then
ssh root@spire-server "rm -rf /opt/spire/data"
ssh root@spire-server2 "rm -rf /opt/spire/data"
fi
