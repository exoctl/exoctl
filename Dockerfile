FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y \
        cmake \
        g++-15 \
        make \
        libyara-dev \
        libclamav-dev \
        binutils \
        git \
        libasio-dev 

COPY . /app
WORKDIR /app

RUN git submodule update --init --recursive

RUN mkdir -p build && \
    cd build && \
    cmake .. && \
    make