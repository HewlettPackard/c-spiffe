# Integration tests

This folder contains all automated integration tests scripts. They were all implemented using Python, with [Behave](https://behave.readthedocs.io/) framework and Shell scripts. All scenarios are written in Gherkin and can be found at `/c-spiffe/integration_test/features`.

## Installing dependencies

- [Docker](https://docs.docker.com/install/)
- [Docker Compose](https://docs.docker.com/compose/install/)

## Running the tests

Inside `c-spiffe/infra` run:
```
$ make integration-tests

    TAG=<image_tag> docker-compose up -d
    Building with native build. Learn about native build in Compose here: https://docs.docker.com/go/compose-native-build/
    Creating network "infra_default" with the default driver
    Creating infra_spire-server2_1 ... done
    Creating infra_spire-server_1  ... done
    Creating infra_workload_1      ... done
    Creating infra_workload2_1     ... done
    Creating infra_tests_1         ... done

    ....

    6 features passed, 0 failed, 0 skipped
    40 scenarios passed, 0 failed, 0 skipped
    466 steps passed, 0 failed, 0 skipped, 0 undefined
    Took 15m11.601s
    docker-compose down
    WARNING: The TAG variable is not set. Defaulting to a blank string.
    Stopping infra_tests_1         ... done
    Stopping infra_workload2_1     ... done
    Stopping infra_workload_1      ... done
    Stopping infra_spire-server_1  ... done
    Stopping infra_spire-server2_1 ... done
    Removing infra_tests_1         ... done
    Removing infra_workload2_1     ... done
    Removing infra_workload_1      ... done
    Removing infra_spire-server_1  ... done
    Removing infra_spire-server2_1 ... done
    Removing network infra_default
```

### Details inside `$ make integration-tests`

This command encapsulates some steps:
1. Start `infra_tests`, `infra_spire-server`, `infra_workload`,  `infra_spire-server2` and `infra_workload2` containers
    - If the images don't exist in the machine, they are automatically pulled:
        - `cspiffe/spire-server:latest`
        - `cspiffe/workload:tag`*
        - `cspiffe/tests:tag`*
        \* the `tag` is replaced as set in the Makefile (`c-spiffe/infra/Makefile`)
2. Configure and enable ssh service for all containers (access granted for `infra_tests` to access the other containers)
3. Build binary files examples (the interface to use c-spiffe lib) inside `infra_workload` and `infra_workload2` containers
4. Inside `infra_tests` container, run `run-behave-tests.sh` script, which encapsulates the following:
    - Build binary files examples (the interface to use c-spiffe lib)
    - Run behave tests
        - Before all the tests are run, this stage is also responsible for starting `spire-agent` process inside `infra_tests` container and connect it to the `spire-server` running inside the `infra_spire-server` container
        - For some particular scenarios, another setup might be executed like starting more `spire-agent` process inside `infra_workload` and `infra_workload2` or a second `spire-server` inside `infra_spire-server2`
5. Stop `infra_tests`, `infra_spire-server`, `infra_workload`,  `infra_spire-server2` and `infra_workload2` containers
