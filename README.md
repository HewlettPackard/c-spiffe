# c-spiffe

C extension for Spiffe platform.

[![Build and run tests](https://github.com/HewlettPackard/c-spiffe/actions/workflows/actions.yml/badge.svg)](https://github.com/HewlettPackard/c-spiffe/actions/workflows/actions.yml)

[![codecov](https://codecov.io/gh/HewlettPackard/c-spiffe/branch/master/graph/badge.svg)](https://codecov.io/gh/HewlettPackard/c-spiffe)

## Introduction

[SPIFFE](https://spiffe.io/) stands for Seurity Identity Framewor for Evertyone and is a set for securely identifying system in dynamic and heteregeous environment. Please refer to https://spiffe.io/docs/latest/spiffe-about/overview/ for more information.  
C-spiffe is a extension for Spiffe that allows any [workload](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#workload) written C, C++ or even any language witch can import a .so library, access [Workload API](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#spiffe-workload-api) and establish a mTLS connection.  
The image above shows a a example, where a C/C++ Workload imports the c-spiffe library in order to fetch a [SVID](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#spiffe-verifiable-identity-document-svid) and use it to establish a mTLS connection with another Workload, that can be implemented using another language, following Spiffe specification.

![Alt text](img/cspiffe_example.png "C-spiffe usage example")

### Motivation

Even though there is an official [c-spiffe](https://github.com/spiffe/c-spiffe) library, we started this one from scratch. We wanted a C implementation (not C++) for better compatibility, and also we based all the design decisions on [go-spiffe](https://github.com/spiffe/c-spiffe), which is the offical supported extension by the Spiffe Community.


## Examples
 
 Refer to [workload/src/Example.MD](workload/src/EXAMPLE.md) for in-depth examples.


## Project structure


### Folders
The project folder structure is described as follows:

* **bundle** Source code for bundle module
* **cmake** Configuration for cmake build
* **docker** Configuration files for container used to build 
* **img** Images files for documentations
* **infra** Container orchestration for tests environment
* **integration_test** Source code for automated test
* **internal** Souce code for internal module
* **protos** Source code for gRPC protos
* **spiffeid** Sour code for spiffeid module
* **spiffetls** Source code for spiffetls module
* **svid** Source code for SVID module
* **utils** Source code for utility functions
* **workload** Source code for workload


### Remarkable files

* [CMakeList.txt](CMakeLists.txt) Main build configuration file. Each source folder also has its own CMake file.
* [README.md](README.md) This README.
* [LICENSE](LICENSE) Project license
* [BUILDING.md](BUILDING.MD) Instructions how to build c-spiffe in your system
* [CONTRIBUTING.md](CONTRIBUTING.md) Guide how to contribute c-spiffe project

<!--TODO: List all folders with its contents -->

## Using C-Spiffe

### Installing



#### Install from source
Reffer to [BUILDING.md](BUILDING.md) 

#### Install on system

We are planning to deliver installers for main Linux distro, but at this momento, only Building from source is supported.

### Basic usage

Refer to [Examples](workload/src/EXAMPLE.md) for more information.



## Contributing
Refer to [Contributing](workload/src/CONTRIBUTING.md) for more information.



## Building

### Docker Building(recommended)

#### Dependencies

* Docker

####  Build Docker Image

```
docker build -f docker/grpc.Dockerfile --build-arg GPRC_VERSION=1.34.0 --build-arg NUM_JOBS=8 --tag grpc-build:1.34.0 .
```

#### Pull our Docker image

````
docker pull willallves/grpc-build:1.34.0
````

#### Run Docker Container

##### Setting volume path: <code>/mnt</code>

```
docker run -it --rm --network host -v $(pwd):/mnt grpc-build:1.34.0
```

##### For Windows 

```
docker run -it --rm --network host -v //c/Repositorios/c-spiffe:/mnt grpc-build:1.34.0
```

##### Building
Build the c-spiffe project:
```
cd /mnt
mkdir build && cd build
cmake ..
make
make test
```
After running `make test`, you will find the test files into `Testing` folder.

### Local building

#### Dependencies

* Gcc
* CMake
* libssl-dev
* liburiparser1
* liburiparser-dev
* protobuf-compiler
* libprotobuf-dev
* check
* lcov
* gcovr
* libjansson-dev
* libcjose-dev
* libgtest-dev
* libgmock-dev

#### Compile GRPC

In order to create a pure C lib, supporting GRPC, wich is a C++ lib, it is necessarty to compile GRPC code together with c-spiffe code. The following steps can be used for compiling GCC:

* Clone GRPC source

Currently, we are using `GRPC_VERSION=1.34.0`

```
cd /tmp && git clone --recurse-submodules -b v${GRPC_VERSION} https://github.com/grpc/grpc
```
*  Build grpc

```
cd /tmp/grpc/cmake/build && cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=ON ../..

# Skipping benchmark tests
RUN sed -i '7,13d' /tmp/grpc/third_party/benchmark/test/cxx03_test.cc 

RUN cd /tmp/grpc/cmake/build && make -j${NUM_JOBS} && make install
```
#### Compile C-Spiffe library

Once you have all the requirements, building is straightfoward with `CMake`

```
mkdir build && cd build
cmake ..
make
make test
```

#### Installing

```
make install
```


### Code Coverage Support

This implements Code Coverage Reports using either using either `gcov` or `lcov`.
If you want to check them, you should run the following command after `make test`:

```
make gcov
make lcov
```

The coverage reports will be into `Coverage` folder. In the case of `lcov`, you
can see into the browser, opening the `index.html` file on the folder above.

# Continuous Integration (CI)

## Operation

Continuous integration (CI) is a practice where a team of developers integrate their code early and often to the main branch or code repository. The goal is to reduce the risk of seeing “integration hell” by waiting for the end of a project or a sprint to merge the work of all developers.

To adopt continuous integration, we will need to run your tests on every change that gets pushed back to the main branch. To do so, you will need to have a service that can monitor your repository and listen to new pushes to the codebase. 

![Alt text](img/ci-process.png "Commit, Build and Deploy")

# Introduction

We only need an existing GitHub repository to create and run a GitHub Actions workflow. In this guide, you'll add a workflow that lints multiple coding languages using the GitHub Super-Linter action. The workflow uses Super-Linter to validate your source code every time a new commit is pushed to your repository.

# To use Github Actions CI/CD, we need:

Most CI tools integrate seamlessly with Git services — especially GitHub.

<ol>
    <li>
    From your repository on GitHub, create a new file in the .github/workflows directory named superlinter.yml.
    </li>
    <li>
    Copy the following YAML contents into the superlinter.yml file. Note: If your default branch is not main, update the value of DEFAULT_BRANCH to match your repository's default branch name.

```
name: Super-Linter

# Run this workflow every time a new commit pushed to your repository
on: push

jobs:
  # Set the job key. The key is displayed as the job name
  # when a job name is not provided
  super-lint:
    # Name the Job
    name: Lint code base
    # Set the type of machine to run on
    runs-on: ubuntu-latest

    steps:
      # Checks out a copy of your repository on the ubuntu-latest machine
      - name: Checkout code
        uses: actions/checkout@v2

      # Runs the Super-Linter action
      - name: Run Super-Linter
        uses: github/super-linter@v3
        env:
          DEFAULT_BRANCH: main
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
</li>
    <li>
    To run your workflow, scroll to the bottom of the page and select Create a new branch for this commit and start a pull request. Then, to create a pull request, click Propose new file.
    </li>
 </ol>

 ![Alt text](img/commit-workflow-file.png)

Committing the workflow file in your repository triggers the push event and runs your workflow.

# Viewing your workflow results

<ol>
    <li>
    On GitHub, navigate to the main page of the repository.
    </li>
    <li>
    Under your repository name, click <b>Actions</b>.

![Alt text](img/actions-tab.png)
    </li>
    <li>
    In the left sidebar, click the workflow you want to see.

![Alt text](img/superlinter-workflow-sidebar.png)
    </li>
    <li>
    From the list of workflow runs, click the name of the run you want to see.

![Alt text](img/superlinter-run-name.png)
    </li>
    <li>
    Under <b>Jobs</b> or in the visualization graph, <b>click the Lint code base</b> job.

![Alt text](img/superlinter-lint-code-base-job-updated.png)
    </li>
    <li>
    Any failed steps are automatically expanded to display the results.

![Alt text](img/super-linter-workflow-results-updated-2.png)
    </li>
</ol>
