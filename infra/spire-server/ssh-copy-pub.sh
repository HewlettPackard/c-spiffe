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
mkdir ~/.ssh
if [ $1 = "workload" ];
then
cp /mnt/c-spiffe/integration_test/helpers/bash-general-scripts/authorized_keys ~/.ssh
elif [ $1 = "spire-server" ];
then
cp /opt/spire/authorized_keys ~/.ssh
fi
