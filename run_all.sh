#!/usr/bin/env bash
# Reproducible test entrypoint for the ERC-8403 POC.
# Layer 1 (python model) and layer 2 (foundry/revm verifier) are reproducible here.
# Layer 3 (live/) needs a running EIP-8141 client and is not run by this script.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
fail=0

echo "== layer 1: python reference model =="
if [ ! -d "$here/.venv" ]; then python3 -m venv "$here/.venv"; fi
"$here/.venv/bin/pip" install -q -r "$here/poc/requirements.txt" || fail=1
"$here/.venv/bin/python" "$here/poc/erc8403_poc.py"     || fail=1
"$here/.venv/bin/python" "$here/poc/erc8403_poc_ext.py" || fail=1

echo
echo "== layer 2: foundry / revm verifier =="
export PATH="$PATH:$HOME/.foundry/bin"
if ! command -v forge >/dev/null 2>&1; then
  echo "forge not found; install foundry (https://getfoundry.sh) to run layer 2"; fail=1
else
  if [ ! -d "$here/evm/lib/forge-std" ]; then
    git clone --depth 1 https://github.com/foundry-rs/forge-std "$here/evm/lib/forge-std" || fail=1
  fi
  ( cd "$here/evm" && forge test -vv ) || fail=1
fi

echo
if [ "$fail" = 0 ]; then echo "ALL REPRODUCIBLE SUITES PASSED"; else echo "SOME SUITES FAILED (see above)"; fi
exit $fail
