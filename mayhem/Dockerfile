FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang cmake libz-dev git

RUN git clone https://github.com/MediaArea/ZenLib/
WORKDIR /ZenLib/Project/CMake/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install

COPY . /repo
WORKDIR /repo/Project/CMake/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_XML_Encode.cpp -fsanitize=fuzzer,address -I /repo/Source/MediaInfo -I /repo/Source/ -I /install/include/ /install/lib/libmediainfo.a /install/lib/libzen.so -lz -o /fuzz

FROM ubuntu:22.04 as package

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y clang cmake libz-dev git

RUN git clone https://github.com/MediaArea/ZenLib/
WORKDIR /ZenLib/Project/CMake/build
RUN cmake .. 
RUN make -j8
RUN make install

COPY --from=builder /fuzz /fuzz_XML_Encode
ENV LD_LIBRARY_PATH=/usr/local/lib