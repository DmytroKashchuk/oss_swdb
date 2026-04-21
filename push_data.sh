#!/usr/bin/env bash
# Sincronizza i CSV locali verso la repo clonata sul server remoto.
# Modalita: add/update (non cancella file sul remote).
# Preserva la struttura delle cartelle.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.sh"

RSYNC_OPTS=(
    -avz                          # archive + verbose + compress
    --prune-empty-dirs            # non creare cartelle vuote sul remote
    --include='*/'                # ricorsione nelle sottocartelle
    --include="${FILE_PATTERN}"   # include i file che ci interessano
    --exclude='*'                 # escludi tutto il resto
    --exclude='.git/'             # safety: mai toccare .git
    -e "ssh -p ${SSH_PORT}"
)

SRC="${LOCAL_PATH}/"
DST="${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}/"

echo "=== PUSH: ${SRC} -> ${DST} ==="
rsync "${RSYNC_OPTS[@]}" "${SRC}" "${DST}"
echo "=== Fatto. ==="