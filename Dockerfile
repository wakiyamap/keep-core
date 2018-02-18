FROM golang:1.9.2

WORKDIR /
RUN apt-get update
RUN apt-get install -y llvm g++ libgmp-dev libssl-dev git-core build-essential
ENV BN_VERSION=c0e5aedc5eeace083e20930b5deb51acefe84cf1
RUN git clone https://github.com/keep-network/bn

WORKDIR /bn/
RUN git reset --hard $BN_VERSION
RUN make && make install

WORKDIR /go/src/github.com/keep-network/keep-core
RUN go get -u github.com/golang/dep/cmd/dep
COPY ./go/Gopkg.toml ./go/Gopkg.lock ./
RUN dep ensure --vendor-only

COPY ./ ./
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o keep-client ./go

ENV LD_LIBRARY_PATH=/usr/local/lib/
ENTRYPOINT ["./keep-client"]
