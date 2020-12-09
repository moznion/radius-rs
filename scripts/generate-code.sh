#!/bin/bash

set -eu

REPO_ROOT="$(cd ./"$(git rev-parse --show-cdup)" || exit; pwd)"
DICTS_DIR="${REPO_ROOT}/dicts"
SRC_DIR="${REPO_ROOT}/radius/src"

DICTS=$(ls "$DICTS_DIR")
DICT_FILES=()

# shellcheck disable=SC2068
for DICT in ${DICTS[@]}; do
  DICT_NAME="${DICT##*.}"
  DICT_FILE="${DICTS_DIR}/dictionary.${DICT_NAME}"
  if [ -f "$DICT_FILE" ]; then
    cat /dev/null > "${SRC_DIR}/${DICT_NAME}.rs"
    DICT_FILES+=("$DICT_FILE")
  fi
done

# shellcheck disable=SC2068
cargo run --bin code-generator -- --out-dir="${SRC_DIR}/" ${DICT_FILES[@]}

cargo fix --allow-dirty --allow-staged
cargo fmt

