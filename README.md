# c-spiffe

C extension for Spiffe platform.

## Introduction

gRPC C++ examples built with CMake.

## Files

```
.
├── docker
|   ├── spiffe.Dockerfile
|   ├── ci.Dockerfile
|   ├── test.Dockerfile
│   └── grpc.Dockerfile
├── worlkload
|   ├── src
|   │   ├── file1.cc
|   │   ├── file2.cc
|   │   ├── file3.cc
|   │   └── CMakeLists.txt
│   ├── tests
|   │   ├── test1
|   │   ├── test2
|   │   ├── test3
|   │   └── CMakeLists.txt 
│   └── CMakeLists.txt
├── bundle
│   ├── jwtbundle
│   │   ├── src
│   │   │   ├── file1.cc
│   │   │   ├── file2.cc
│   │   │   ├── file3.cc
|   │   │   └── CMakeLists.txt 
│   │   ├── tests
|   │   │   ├── test1
|   │   │   ├── test2
|   │   │   ├── test3
|   │   │   └── CMakeLists.txt 
│   │   └── CMakeLists.txt
│   ├── spiffebundle
│   │   ├── src
│   │   │   ├── file1.cc
│   │   │   ├── file2.cc
│   │   │   ├── file3.cc
|   │   │   └── CMakeLists.txt 
│   │   ├── tests
|   │   │   ├── test1
|   │   │   ├── test2
|   │   │   ├── test3
|   │   │   └── CMakeLists.txt 
│   │   └── CMakeLists.txt
│   ├── x509bundle
│   │   ├── src
│   │   │   ├── file1.cc
│   │   │   ├── file2.cc
│   │   │   ├── file3.cc
|   │   │   └── CMakeLists.txt 
│   │   ├── tests
|   │   │   ├── test1
|   │   │   ├── test2
|   │   │   ├── test3
|   │   │   └── CMakeLists.txt
|   |   └── CMakeLists.txt
│   └── CMakeLists.txt
├── CMakeLists.txt
├── LICENSE.md
├── protos
│   ├── workload.proto
└── README.md
```

## Dependencies

* gRPC 1.34
* CMake 3.13.0+

##  Build Docker Image

```
docker build -f docker/grpc.Dockerfile --build-arg GPRC_VERSION=1.34.0 --build-arg NUM_JOBS=8 --tag grpc-build:1.34.0 .
```

## Run Docker Container

#### setting volume path: <code>/mnt</code>

```
docker run -it --rm --network host -v $(pwd):/mnt grpc-build:1.34.0
```

# For Windows 

```
docker run -it --rm --network host -v //c/Repositorios/c-spiffe:/mnt grpc-build:1.34.0
```

## Building
Build the c-spiffe project:

```bash
cd /mnt/ (*volume set path)
cmake -B build
cmake --build build --config Release --parallel
```
cd /mnt
mkdir build && cd build
cmake ..
make
make test
```
After running `make test`, you will find the test files into `Testing` folder.

### Code Coverage Support

This implements Code Coverage Reports using either using either `gcov` or `lcov`.
If you want to check them, you should run the following command after `make test`:

```
make gcov
make lcov
```

The coverage reports will be into `Coverage` folder. In the case of `lcov`, you
can see into the browser, opening the `index.html` file on the folder above.
