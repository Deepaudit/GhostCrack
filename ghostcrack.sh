#!/usr/bin/env bash
#
# =====================================================================
#  GhostCrack.sh - Launcher oficial (Bash) do GhostCrack
#  Autores: pablocybersec & prof. 0xGhostSec
#
#  Este script é o ponto de entrada recomendado para os alunos.
#  Ele verifica dependências, localiza o Python 3 e repassa os
#  argumentos para o motor em Python (ghostcrack.py).
#
#  Se o Python 3 não estiver disponível, o script sugere o uso do
#  cracker alternativo 100% Bash (bash-cracker.sh).
# =====================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_ENGINE="${SCRIPT_DIR}/ghostcrack.py"

RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

find_python() {
    if command -v python3 &>/dev/null; then
        echo "python3"
        return 0
    fi
    if command -v python &>/dev/null; then
        # confirma que é Python 3
        if python -c 'import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)' &>/dev/null; then
            echo "python"
            return 0
        fi
    fi
    return 1
}

main() {
    if [[ ! -f "$PY_ENGINE" ]]; then
        echo -e "${RED}[x] Não encontrei ghostcrack.py em: ${PY_ENGINE}${NC}" >&2
        exit 1
    fi

    PYBIN="$(find_python || true)"

    if [[ -z "${PYBIN:-}" ]]; then
        echo -e "${YELLOW}[!] Python 3 não encontrado neste sistema.${NC}" >&2
        echo -e "${YELLOW}[!] Use o cracker alternativo 100% Bash: ./bash-cracker.sh${NC}" >&2
        exit 1
    fi

    if [[ $# -eq 0 ]]; then
        "$PYBIN" "$PY_ENGINE" --help
        echo -e "\n${CYAN}Dica:${NC} veja também ./bash-cracker.sh (versão pura Bash) e ./encode-decode.sh (utilitário rápido)."
        exit 0
    fi

    exec "$PYBIN" "$PY_ENGINE" "$@"
}

main "$@"
