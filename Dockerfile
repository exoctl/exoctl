FROM debian:latest

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libasio-dev \ 
    libyara-dev \ 
    libsqlite3-dev

WORKDIR /usr/sources/
COPY . .

EXPOSE 8181

RUN git submodule update --init --recursive
RUN mkdir build && cd build && cmake .. && make

CMD ["./build/sources/engine"]