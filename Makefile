VERSION=`git rev-parse --short HEAD`
OS := $(shell uname)
ifeq ($(OS),Darwin)
flags=-ldflags="-s -w -X main.version=${VERSION}"
else
flags=-ldflags="-s -w -X main.version=${VERSION} -extldflags -static"
endif

all: build

vet:
	go vet .

build:
	go clean; CGO_ENABLED=0 go build -o gocurl ${flags}

build_debug:
	go clean; CGO_ENABLED=0 go build -o gocurl ${flags} -gcflags="-m -m"

build_all: build_darwin build_amd64 build_power8 build_arm64 build_windows

build_darwin:
	go clean; rm gocurl_darwin; GOOS=darwin CGO_ENABLED=0 go build -o gocurl_darwin ${flags}

build_amd64:
	go clean; rm gocurl_amd64; GOOS=linux CGO_ENABLED=0 go build -o gocurl_amd64 ${flags}

build_power8:
	go clean; rm gocurl_power8; GOARCH=ppc64le GOOS=linux CGO_ENABLED=0 go build -o gocurl_power8 ${flags}

build_arm64:
	go clean; rm gocurl_arm64; GOARCH=arm64 GOOS=linux CGO_ENABLED=0 go build -o gocurl_arm64 ${flags}

build_windows:
	go clean; rm gocurl_windows; GOARCH=amd64 GOOS=windows CGO_ENABLED=0 go build -o gocurl_windows ${flags}

clean:
	go clean

test:
	go test -v -bench=.
