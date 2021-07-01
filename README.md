# c-spiffe

C extension for Spiffe platform.

[![Build and run tests](https://github.com/HewlettPackard/c-spiffe/actions/workflows/actions.yml/badge.svg)](https://github.com/HewlettPackard/c-spiffe/actions/workflows/actions.yml)

[![codecov](https://codecov.io/gh/HewlettPackard/c-spiffe/branch/master/graph/badge.svg)](https://codecov.io/gh/HewlettPackard/c-spiffe)

[![release](https://img.shields.io/badge/release-v1.0.0-yellow.svg)](https://github.com/willallves/c-spiffe/archive/refs/tags/1.0.0.zip)

## Introduction

[SPIFFE](https://spiffe.io/) stands for Security Identity Framework for Everyone and is a set for securely identifying system in dynamic and heterogeneous environment. Please refer to [SPIFFE Documentation](https://spiffe.io/docs/latest/spiffe-about/overview/) for more information.  
C-spiffe is an extension for Spiffe that allows any [workload](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#workload) written C, C++ or  any language that supports loading a .so library, access [Workload API](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#spiffe-workload-api) and establish a mTLS connection with other workloads.  
The image above shows an example, where a C/C++ Workload imports the c-spiffe library in order to fetch a [SVID](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#spiffe-verifiable-identity-document-svid) and use it to establish a mTLS connection with another Workload, which can be implemented in another language, provided it follows the SPIFFE standard.

![Alt text](img/cspiffe_example.png "C-spiffe usage example")

### Motivation

Even though there is an official [c-spiffe](https://github.com/spiffe/c-spiffe) library, we started this one from scratch. We wanted a C implementation (not C++) for better compatibility. We also based most of the design decisions on [go-spiffe](https://github.com/spiffe/go-spiffe), which is the offical supported extension by the Spiffe Community.

## Project structure

### Folders

The project folder structure is described as follows:

* **bundle** Source code for bundle module
* **cmake** Configuration for cmake build
* **docker** Configuration files for container used to build this lib
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
* [LICENSE](LICENSE) Project license.
* [BUILDING.md](BUILDING.md) Instructions on how to build c-spiffe in your system.
* [CONTRIBUTING.md](CONTRIBUTING.md) Guidelines for contributing to c-spiffe project.
* [MINIMAL INSTALLATION](MINOR-INSTALLATION.md) Minimal Installation.

## Using C-Spiffe

### Installing

#### Install from source

Reffer to [BUILDING.md](BUILDING.md)

#### Install on system

We are planning on delivering package for the most popular Linux distros, but at this moment, only building from source is supported.

### Basic usage

Refer to [Examples](workload/EXAMPLE.md) for more information.

## Initial Contributors

* Ariana Guimarães
* Débora Silva
* Glaucimar Aguiar
* Otávio Silva
* Rodrigo Carvalho
* Thiago Jamir
* Willian Alves

## Contributing

Refer to [Contributing](CONTRIBUTING.md) for more information.
