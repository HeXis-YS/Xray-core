#!/bin/bash
for goamd64 in v2 v2e v3
do
    CGO_ENABLED=0 GOAMD64=${goamd64} GOOS=linux go build -o xray_linux_amd64_${goamd64} -trimpath -gcflags=all="-B" -ldflags="-X github.com/xtls/xray-core/core.build=$(git describe --tags) -s -w -stripfn 2 -buildid=" ./main
    strip -s -R .gosymtab -R .go.buildinfo xray_linux_amd64_${goamd64}
    sstrip -z xray_linux_amd64_${goamd64}
done

for goamd64 in v2 v3
do
    CGO_ENABLED=0 GOAMD64=${goamd64} GOOS=windows go build -o xray_windows_amd64_${goamd64}.exe -trimpath -gcflags=all="-B" -ldflags="-X github.com/xtls/xray-core/core.build=$(git describe --tags) -s -w -stripfn 2 -buildid=" ./main
done
