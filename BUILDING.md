# Building

## Docker Building (recommended)

### Docker Build Dependencies

* Docker

### Build Docker Image

You can build the docker image from source with the following command line:

```bash
git clone git@github.com:HewlettPackard/c-spiffe.git
cd c-spiffe
docker build -f docker/grpc.Dockerfile --build-arg GPRC_VERSION=1.34.0 --build-arg NUM_JOBS=8 --tag grpc-build:1.34.0 .
```

### Pull our Docker image

Or you can use a pre-built image:

````bash
docker pull willallves/grpc-build:1.34.0
````

#### Run Docker Container

##### Setting volume path: `/mnt/`

```bash
docker run -it --rm --network host -v $(pwd):/mnt grpc-build:1.34.0
```

##### For Windows

```bash
docker run -it --rm --network host -v <ABSOLUTE_PATH_TO_CSPIFFE>:/mnt grpc-build:1.34.0
```

In the path `ABSOLUTE_PATH_TO_CSPIFFE`, start with `//` and don't use `:`. For example, if your code is in `C:\repositories\c-spiffe`, then you'll run:

```bash
docker run -it --rm --network host -v //c/repositories/c-spiffe:/mnt grpc-build:1.34.0
```

#### Docker Building

Build the c-spiffe project:

```bash
cd /mnt
mkdir build && cd build
cmake ..
make
make test
```

After running `make test`, you will find the test files in the `Testing` folder.

## Local building

### Local Build Dependencies

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

### Compile gRPC

In order to create a pure C lib, supporting gRPC, which is a C++ lib, it is necessarty to compile gRPC code together with c-spiffe code. The following steps can be used for compiling gRPC:

* Clone GRPC source

Currently, we are using `GRPC_VERSION=1.34.0`

```bash
cd /tmp && git clone --recurse-submodules -b v${GRPC_VERSION} https://github.com/grpc/grpc
```

* Build grpc

```bash
cd /tmp/grpc/cmake/build && cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=ON ../..

# Skipping benchmark tests
RUN sed -i '7,13d' /tmp/grpc/third_party/benchmark/test/cxx03_test.cc 

RUN cd /tmp/grpc/cmake/build && make -j${NUM_JOBS} && make install
```

### Compile C-Spiffe library

Once you meet all the requirements, building is straightforward with `CMake`

```bash
mkdir build && cd build
cmake ..
make
make test
```

### Installing

```bash
make install
```

## Code Coverage Support

This project generates Code Coverage Reports using either `gcov` and `lcov`.
If you want to generate cover reports, you should run the following command after `make test`:

```bash
make gcov
make lcov
```

The coverage reports will be written to the `Coverage` folder. In the case of `lcov`, you
can see it opening the `index.html` file on the folder above in your browser.
