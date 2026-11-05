#!/bin/sh
# Build static release archives and SHA256SUMS.
# Usage: scripts/build-release.sh <version> <outdir>
set -eu
version=$1
out=$2
rm -rf "$out"
mkdir -p "$out"
for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64; do
	os=${target%/*}
	arch=${target#*/}
	name="netwatch_${version}_${os}_${arch}"
	dir="$out/$name"
	mkdir -p "$dir"
	bin=netwatch
	[ "$os" = windows ] && bin=netwatch.exe
	GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X main.version=$version" -o "$dir/$bin" ./cmd/netwatch
	# A guardtest build (danger injection, test-daemon kill tier) must never
	# ship. Check the binary's recorded build settings, whatever GOFLAGS was.
	if go version -m "$dir/$bin" | grep -q -- '-tags=.*guardtest'; then
		echo "build-release: $name was built with the guardtest tag; refusing" >&2
		exit 1
	fi
	cp README.md LICENSE "$dir/"
	if [ "$os" = windows ]; then
		(cd "$out" && zip -qr "$name.zip" "$name")
	else
		tar -C "$out" -czf "$out/$name.tar.gz" "$name"
	fi
	rm -rf "$dir"
done
(cd "$out" && { command -v sha256sum >/dev/null && sha256sum ./*.tar.gz ./*.zip || shasum -a 256 ./*.tar.gz ./*.zip; } | sed 's# \./# #' > SHA256SUMS)
cat "$out/SHA256SUMS"
