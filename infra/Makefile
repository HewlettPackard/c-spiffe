build:
	docker build spire-agent -t spire-agent
	docker-compose build

build-tests-workload:
	docker-compose exec workload ./build-tests-workload.sh

run:
	docker-compose up -d

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
	TAG=test-202-Implement-test-case-FXB_01 docker-compose up -d

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
