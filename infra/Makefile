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

run:
	TAG=$(TAG) docker-compose up -d

run-server:
	docker-compose exec spire-server spire-server run

create-entries:
	docker-compose exec spire-server ./create-entries.sh

generate-token:
	docker-compose exec spire-server spire-server token generate -spiffeID spiffe://example.org/host

join-token:
	docker-compose exec $(SERVICE) spire-agent run -joinToken $(TOKEN) -config /opt/spire/conf/agent/agent.conf

clean:
	docker-compose down

integration-tests:
	TAG=$(TAG) docker-compose up -d

	docker exec infra_workload_1 service ssh restart
	docker exec infra_workload2_1 service ssh restart
	docker exec infra_tests_1 service ssh restart
	docker exec infra_spire-server_1 service ssh restart
	docker exec infra_spire-server2_1 service ssh restart
	docker exec -w /mnt/c-spiffe/integration_test/helpers/bash-general-scripts infra_tests_1 ./ssh-generate-pub.sh
	docker exec -w /mnt/c-spiffe/integration_test/helpers/bash-general-scripts infra_tests_1 cat authorized_keys > authorized_keys && docker cp authorized_keys infra_workload_1:/mnt/c-spiffe/integration_test/helpers/bash-general-scripts
	docker cp authorized_keys infra_workload2_1:/mnt/c-spiffe/integration_test/helpers/bash-general-scripts
	docker cp authorized_keys infra_spire-server_1:/opt/spire
	docker cp authorized_keys infra_spire-server2_1:/opt/spire && rm authorized_keys
	docker exec -w /mnt/c-spiffe/integration_test/helpers/bash-general-scripts infra_workload_1 ./ssh-copy-pub.sh workload
	docker exec -w /mnt/c-spiffe/integration_test/helpers/bash-general-scripts infra_workload2_1 ./ssh-copy-pub.sh workload
	docker exec -w /opt/spire infra_spire-server_1 ./ssh-copy-pub.sh spire-server
	docker exec -w /opt/spire infra_spire-server2_1 ./ssh-copy-pub.sh spire-server
	docker exec -w /mnt/c-spiffe/integration_test/helpers/bash-general-scripts infra_tests_1 ./ssh-trusted-host.sh
	docker exec -w /mnt/c-spiffe/infra/tests infra_workload_1 ./build-examples.sh
	docker exec -w /mnt/c-spiffe/infra/tests infra_workload2_1 ./build-examples.sh

	docker exec -w /mnt/c-spiffe/integration_test/helpers/bash-general-scripts infra_tests_1 ./run-behave-tests.sh
	docker-compose down
