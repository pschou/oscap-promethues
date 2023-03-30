VERSION = 0.1.$(shell date +%Y%m%d.%H%M)
FLAGS := "-s -w -X main.version=${VERSION}"

xml:
	CGO_ENABLED=0 go build -ldflags=${FLAGS} oscap-prom.go
	upx --lzma oscap-prom
