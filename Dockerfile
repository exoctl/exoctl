FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++-14 \
    gcc \
    make \
    cmake \
    git \
    libasio-dev \
    ca-certificates \
    libyara-dev \
    libsqlite3-dev \
    libclamav-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
RUN update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-14 100

WORKDIR /opt

COPY . .

EXPOSE 8081

RUN git submodule update --init --recursive
RUN mkdir build && \
    cd build && \
    cmake -DCMAKE_CXX_COMPILER=g++ -DCMAKE_C_COMPILER=gcc .. && \
    make && \
    rm -rf /var/lib/apt/lists/*

CMD ["./build/sources/engine"]