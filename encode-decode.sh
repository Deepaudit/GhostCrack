#!/usr/bin/env bash
#
# =====================================================================
#  encode-decode.sh - Utilitário rápido de encoding/hashing (Bash puro)
#  Autores: pablocybersec & prof. 0xGhostSec
#
#  Gera MD5 / SHA1 / SHA256 / SHA512 / Base64 de um texto ou arquivo,
#  e decodifica Base64/Hex. Não depende de Python.
# =====================================================================

set -o pipefail

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

usage() {
    cat << EOF
${BOLD}encode-decode.sh${NC} - GhostCrack utils (pablocybersec & prof. 0xGhostSec)

Uso:
  Codificar (gera hashes + base64):
    $0 --encode -t "texto"          Codifica uma string
    $0 --encode -f arquivo.txt      Codifica o conteúdo de um arquivo
    $0 --encode -t "texto" -a md5   Mostra somente o algoritmo escolhido
                                     (md5|sha1|sha256|sha512|base64|all - padrão: all)

  Decodificar (somente reversíveis):
    $0 --decode -t "SGVsbG8="       Decodifica Base64
    $0 --decode -t "48656c6c6f" -a hex
                                     Decodifica Hex

  Identificar algoritmo pelo tamanho da hash:
    $0 --identify "5f4dcc3b5aa765d61d8327deb882cf99"

Opções:
  -t, --text <string>    Texto de entrada
  -f, --file <arquivo>   Arquivo de entrada
  -a, --algo <tipo>      md5 | sha1 | sha256 | sha512 | base64 | hex | all
  -h, --help             Ajuda

EOF
    exit 1
}

require_cmd() {
    command -v "$1" &>/dev/null || { echo -e "${RED}[x] Comando ausente: $1${NC}" >&2; exit 1; }
}

do_encode() {
    local text="$1" file="$2" algo="${3:-all}"
    local data_source

    if [[ -n "$file" ]]; then
        [[ -f "$file" ]] || { echo -e "${RED}[x] Arquivo não encontrado: $file${NC}" >&2; exit 1; }
        data_source="cat \"$file\""
        echo -e "${BOLD}Entrada:${NC} <arquivo: $file>"
    else
        data_source="printf '%s' \"$text\""
        echo -e "${BOLD}Entrada:${NC} $text"
    fi
    echo ""

    if [[ "$algo" == "base64" || "$algo" == "all" ]]; then
        require_cmd base64
        local b64
        b64=$(eval "$data_source" | base64 | tr -d '\n')
        echo -e "  ${CYAN}base64 ${NC}: $b64"
    fi

    local -A cmds=( [md5]=md5sum [sha1]=sha1sum [sha256]=sha256sum [sha512]=sha512sum )
    local order=(md5 sha1 sha256 sha512)

    for a in "${order[@]}"; do
        if [[ "$algo" == "$a" || "$algo" == "all" ]]; then
            require_cmd "${cmds[$a]}"
            local h
            h=$(eval "$data_source" | "${cmds[$a]}" | awk '{print $1}')
            echo -e "  ${CYAN}${a}$(printf '%*s' $((7 - ${#a})) '')${NC}: $h"
        fi
    done
}

do_decode() {
    local text="$1" file="$2" algo="${3:-base64}"
    local input="$text"

    if [[ -n "$file" ]]; then
        [[ -f "$file" ]] || { echo -e "${RED}[x] Arquivo não encontrado: $file${NC}" >&2; exit 1; }
        input=$(cat "$file")
    fi

    case "$algo" in
        base64)
            require_cmd base64
            if echo -n "$input" | base64 -d > /tmp/.ghostcrack_decoded 2>/dev/null; then
                echo -e "${GREEN}[+] Decodificado:${NC} $(cat /tmp/.ghostcrack_decoded)"
                rm -f /tmp/.ghostcrack_decoded
            else
                echo -e "${RED}[x] Falha ao decodificar Base64 (entrada inválida).${NC}" >&2
                exit 1
            fi
            ;;
        hex)
            if echo -n "$input" | xxd -r -p > /tmp/.ghostcrack_decoded 2>/dev/null; then
                echo -e "${GREEN}[+] Decodificado:${NC} $(cat /tmp/.ghostcrack_decoded)"
                rm -f /tmp/.ghostcrack_decoded
            else
                echo -e "${RED}[x] Falha ao decodificar Hex (xxd necessário).${NC}" >&2
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}[x] Algoritmo de decodificação inválido: $algo (use base64 ou hex)${NC}" >&2
            exit 1
            ;;
    esac
}

do_identify() {
    local h="$1"
    h="${h,,}"  # lowercase
    local len=${#h}
    local algo=""
    case "$len" in
        32) algo="md5" ;;
        40) algo="sha1" ;;
        64) algo="sha256" ;;
        128) algo="sha512" ;;
    esac

    if [[ -n "$algo" ]]; then
        echo -e "${GREEN}[+]${NC} Provável algoritmo: ${BOLD}${algo}${NC} (tamanho: ${len} hex chars)"
    else
        echo -e "${CYAN}[!]${NC} Não identificado pelo tamanho (${len} chars). Tamanhos conhecidos: 32=MD5, 40=SHA1, 64=SHA256, 128=SHA512"
    fi
}

MODE=""
TEXT=""
FILE=""
ALGO=""

[[ $# -eq 0 ]] && usage

while [[ $# -gt 0 ]]; do
    case "$1" in
        --encode) MODE="encode"; shift ;;
        --decode) MODE="decode"; shift ;;
        --identify) MODE="identify"; TEXT="$2"; shift 2 ;;
        -t|--text) TEXT="$2"; shift 2 ;;
        -f|--file) FILE="$2"; shift 2 ;;
        -a|--algo) ALGO="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Argumento desconhecido: $1" >&2; usage ;;
    esac
done

case "$MODE" in
    encode) do_encode "$TEXT" "$FILE" "${ALGO:-all}" ;;
    decode) do_decode "$TEXT" "$FILE" "${ALGO:-base64}" ;;
    identify) do_identify "$TEXT" ;;
    *) usage ;;
esac
