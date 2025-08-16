FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y \
        build-essential \
        g++-14 \
        gcc \
        libyara-dev \
        libclamav-dev \
        binutils \
        git \
        libsqlite3-dev \
        curl \
        unzip \
        libmysqlclient-dev \
        libpq-dev \
        clamav \
        libasio-dev

RUN curl -LO https://github.com/Kitware/CMake/releases/download/v3.29.4/cmake-3.29.4-linux-x86_64.sh && \
    chmod +x cmake-3.29.4-linux-x86_64.sh && \
    ./cmake-3.29.4-linux-x86_64.sh --skip-license --prefix=/usr/local && \
    rm cmake-3.29.4-linux-x86_64.sh

COPY . /app
WORKDIR /app

RUN git submodule update --init --recursive
RUN freshclam

RUN mkdir -p build && cd build && \
    cmake .. && \
    make
