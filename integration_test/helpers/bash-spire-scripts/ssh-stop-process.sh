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

#!/usr/bin/env bash
#arguments: $1 = 'server' or 'agent'; $2 = hostname; $3 = workload_id (optional)
if [ $3 ];
then
TOKEN=$(awk '{ print $2 }' /mnt/c-spiffe/integration_test/myagent${3}.token)
ssh root@$2 "ps aux | grep spire-${1} | grep ${TOKEN} | awk '{ print \$2 }' | xargs -I {} kill -9 {}"
else
ssh root@$2 "pkill -9 spire-$1"
fi
