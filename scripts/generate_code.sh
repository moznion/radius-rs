#!/bin/bash

set -eu

REPO_ROOT="$(cd ./"$(git rev-parse --show-cdup)" || exit; pwd)"
DICTS_DIR="${REPO_ROOT}/dicts"
SRC_DIR="${REPO_ROOT}/src"

DICTS=$(ls "$DICTS_DIR")

# shellcheck disable=SC2068
for DICT in ${DICTS[@]}; do
  DICT_NAME="${DICT##*.}"
  cat /dev/null > "${SRC_DIR}/${DICT_NAME}.rs"
  cargo run --bin code_gen "${DICTS_DIR}/dictionary.${DICT_NAME}" "${SRC_DIR}/${DICT_NAME}.rs"
done

cargo fmt

