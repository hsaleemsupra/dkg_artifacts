# Scalable Distributed Key Generation for Blockchains

## Overview

This repository contains the implementation code for the paper "Scalable Distributed Key Generation for Blockchains."

## Running Benchmarks

The simplest way to run the benchmarks is using a docker container

1. Install docker engine using these instructions: [docker engine](https://docs.docker.com/engine/install/ "docker engine") 

2. Once the docker engine is installed and running, clone this repo and build the docker image as follows:

    ```
     cd dkg_artifact
     docker build -t dkg_app .
    ```
    
3. After building the docker image, run it using:

    ```
     docker run --rm dkg_app
    ```

4. Running the docker container should run benchmarks for dkg run for various committee settings: **(tribe, clan, family) = [(64, 42, 14), (96, 64, 16), (128, 80, 17)]**. Note these benchmarks are run locally on a single machine and not in a distributed setting which requires network setup. 

**NOTE**

Running benchmarks in Docker can be affected by the Docker runtime environment. The results might not fully reflect the performance characteristics that would be observed running directly on the host due to the overhead and resource limitations imposed by Docker.

Alternately, running the benchmarks directly on the host machine requires manually installing dependencies including, rust, cmake, clang, openssl, gmp. Here is an example of running the benchmarks directly on a Ubuntu host.

1. Install rust using the instructions here: [rust](https://www.rust-lang.org/tools/install "rust").

2. Install dependencies as follows:

    ```
    sudo apt-get update
    sudo apt-get install build-essential cmake pkg-config libclang-dev libssl-dev libgmp-dev
    ```

3. Clone the repo and run:

    ```
    cd dkg_artifact
    cargo build --release
    cargo bench --bench dkg_bench -- --quick 
    ```
