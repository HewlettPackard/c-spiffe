
# Building

## Docker Building(recommended)

### Dependencies

* Docker

###  Build Docker Image

You can build the docker image from source with the above command line:

```
docker build -f docker/grpc.Dockerfile --build-arg GPRC_VERSION=1.34.0 --build-arg NUM_JOBS=8 --tag grpc-build:1.34.0 .
```

### Pull our Docker image

Or you can use a pre build image:

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
docker run -it --rm --network host -v <ABSOLUTE_PATH_TO_CSPIFFE>:/mnt grpc-build:1.34.0
```
In the path `ABSOLUTE_PATH_TO_CSPIFFE`, start with `//` and don't use `:`. For example, if your code is in `C:\repositories\c-spiffe`, then you'll run:

```
docker run -it --rm --network host -v //c/repositories/c-spiffe:/mnt grpc-build:1.34.0
```

#### Building
Build the c-spiffe project:
```
cd /mnt
mkdir build && cd build
cmake ..
make
make test
```
After running `make test`, you will find the test files into `Testing` folder.

## Local building

### Dependencies

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

### Compile GRPC

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
### Compile C-Spiffe library

Once you have all the requirements, building is straightfoward with `CMake`

```
mkdir build && cd build
cmake ..
make
make test
```

### Installing

```
make install
```


## Code Coverage Support

This implements Code Coverage Reports using either using either `gcov` or `lcov`.
If you want to check them, you should run the following command after `make test`:

```
make gcov
make lcov
```

The coverage reports will be into `Coverage` folder. In the case of `lcov`, you
can see into the browser, opening the `index.html` file on the folder above.