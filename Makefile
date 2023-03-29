VERSION = 0.1.$(shell date +%Y%m%d.%H%M)
FLAGS := "-s -w -X main.version=${VERSION}"

xml:
	go build ResultToProm.go
	upx --lzma ResultToProm
