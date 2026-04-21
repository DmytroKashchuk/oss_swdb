#!/usr/bin/env bash
# Sincronizza i CSV dal server remoto verso la cartella locale del progetto.
# Modalita: add/update (non cancella file in locale).
# Preserva la struttura delle cartelle.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.sh"

RSYNC_OPTS=(
    -avz
    --prune-empty-dirs
    --include='*/'
    --include="${FILE_PATTERN}"
    --exclude='*'
    --exclude='.git/'
    -e "ssh -p ${SSH_PORT}"
)

SRC="${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}/"
DST="${LOCAL_PATH}/"

echo "=== PULL: ${SRC} -> ${DST} ==="
rsync "${RSYNC_OPTS[@]}" "${SRC}" "${DST}"
echo "=== Fatto. ==="