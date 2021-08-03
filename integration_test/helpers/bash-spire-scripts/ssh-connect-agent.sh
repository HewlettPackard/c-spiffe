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
#arguments: $1 = workload_id; $2 = hostname (optional)
TOKEN=$(awk '{ print $2 }' /mnt/c-spiffe/integration_test/myagent$1.token)
if [ $2 ];
then
ssh root@$2 <<EOL
    nohup spire-agent run -joinToken ${TOKEN} -config /opt/spire/conf/agent/agent${1}.conf> /dev/null 2>&1 & 
EOL
else
    spire-agent run -joinToken $TOKEN -config /opt/spire/conf/agent/agent.conf> /dev/null 2>&1 & 
fi
