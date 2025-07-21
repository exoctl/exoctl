FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y \
        cmake \
        g++-15 \
        gcc \
        make \
        libyara-dev \
        libclamav-dev \
        binutils \
        git \ 
        freshclam \
        libasio-dev
    
COPY . /app
WORKDIR /app

RUN git submodule update --init --recursive
RUN freshclam

# make engine
RUN mkdir -p build && \
    cd build && \
    cmake -DCMAKE_CXX_COMPILER=g++ .. && \
    make
