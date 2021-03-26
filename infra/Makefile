build:
	docker build spire-agent -t spire-agent
	docker-compose build

build-tests-workload:
	docker-compose exec workload ./build-tests-workload.sh

run:
	docker-compose up -d

run-server:
	docker-compose exec spire-server ./init-server.sh

create-entries:
	docker-compose exec spire-server ./create-entries.sh

generate-token:
	docker-compose exec spire-server spire-server token generate -spiffeID spiffe://example.org/host

join-token:
	docker-compose exec $(SERVICE) spire-agent run -joinToken $(TOKEN) -config /opt/spire/conf/agent/agent.conf

clean:
	docker-compose down

integrations-tests:
	docker-compose up -d
	docker exec infra_spire-server_1 spire-server run &
	docker exec infra_spire-server_1 spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myworkload -selector unix:user:root &
	docker exec infra_spire-server_1 spire-server token generate -spiffeID spiffe://example.org/myagent > token
	docker cp token infra_tests_1:/mnt/c-spiffe/integration_test
	docker exec infra_tests_1 ./connect_agent.sh
	docker exec -w /mnt/c-spiffe/build infra_tests_1 cmake ..
	docker exec -w /mnt/c-spiffe/build infra_tests_1 make
	docker exec -w /mnt/c-spiffe/integration_test infra_tests_1 behave --tags=-@wip
	docker-compose down
