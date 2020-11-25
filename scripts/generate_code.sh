#!/bin/bash

set -eu

REPO_ROOT="$(cd ./"$(git rev-parse --show-cdup)" || exit; pwd)"

DICT_NAMES=(
  "rfc2865"
)

for DICT_NAME in "${DICT_NAMES[@]}"; do
  cat /dev/null > "${REPO_ROOT}/src/${DICT_NAME}.rs"
  cargo run --bin code_gen "${REPO_ROOT}/dicts/dictionary.${DICT_NAME}" "${REPO_ROOT}/src/${DICT_NAME}.rs"
done

cargo fmt

