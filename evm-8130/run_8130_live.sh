#!/usr/bin/env bash
set -u
here="$(cd "$(dirname "$0")" && pwd)"
export PATH="$PATH:$HOME/.foundry/bin"
PIN=812317be00d6829e217e0cc92f75be362fde0711
SRC="$here/base"

if ! command -v forge >/dev/null 2>&1; then
  echo "forge not found; install foundry (https://getfoundry.sh)"; exit 1
fi
if [ ! -d "$SRC/.git" ]; then
  git clone https://github.com/base/eip-8130 "$SRC" || exit 1
fi
( cd "$SRC" && git checkout "$PIN" && git submodule update --init --recursive ) || exit 1
cp "$here/ERC8403ReadForm8130.t.sol" "$SRC/test/ERC8403ReadForm8130.t.sol"
( cd "$SRC" && forge test --match-contract ERC8403ReadForm8130 -vv )
