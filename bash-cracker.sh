#!/usr/bin/env bash
#
# =====================================================================
#  bash-cracker.sh - Hash Cracker 100% Bash (sem dependência de Python)
#  Autores: pablocybersec & prof. 0xGhostSec
#
#  Ataque de dicionário contra MD5 / SHA1 / SHA256 / SHA512 usando
#  apenas ferramentas GNU coreutils (md5sum, sha1sum, sha256sum,
#  sha512sum) + xargs para paralelismo real.
#
#  AVISO: use somente em hashes que você tem autorização para testar.
# =====================================================================

set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

VERSION="1.0"
HASH_FILE=""
WORDLIST=""
ALGO="auto"
THREADS=4
OUTPUT=""
QUIET=false
SALT_PREFIX=""
SALT_SUFFIX=""
STOP_ON_ALL=false

banner() {
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
   ______ __              __   ______                __
  / ____// /_   ____   ___/ /_ / ____/_____ ____ _ _____ / /__
 / / __ / __ \ / __ \ / ___// // /    / ___// __ `// ___// //_/
/ /_/ // / / // /_/ /(__  )/ /_/ /___ / /   / /_/ // /__ / ,<
\____//_/ /_/ \____/____/  \____/\____//_/    \__,_/ \___//_/|_|
EOF
    echo -e "${NC}${BOLD}   bash-cracker.sh v${VERSION} - GhostCrack (pablocybersec & prof. 0xGhostSec)${NC}"
    echo -e "${CYAN}   Hash Cracker 100% Bash - dicionário/wordlist${NC}\n"
}

usage() {
    banner
    cat << EOF
Uso:
  $0 -f <arquivo_hashes> -w <wordlist> [opções]

Obrigatórios:
  -f, --hash-file <arquivo>   Arquivo com a(s) hash(es). Uma por linha.
                               Formatos aceitos: "hash" ou "usuario:hash"
  -w, --wordlist <arquivo>    Wordlist a ser usada no ataque de dicionário.

Opções:
  -a, --algo <tipo>           md5 | sha1 | sha256 | sha512 | auto (padrão: auto,
                               detecta pelo tamanho da hash: 32/40/64/128 hex)
  -t, --threads <n>           Threads paralelas via xargs (padrão: ${THREADS})
  -o, --output <arquivo>      Salva resultado (hash:senha) em arquivo
  -P, --salt-prefix <str>     Prefixo de salt (concatenado antes do candidato)
  -S, --salt-suffix <str>     Sufixo de salt (concatenado depois do candidato)
  -s, --stop-on-all-found     Para assim que todas as hashes forem quebradas
  -q, --quiet                 Modo silencioso
  -h, --help                  Mostra esta ajuda
  -v, --version                Mostra a versão

Exemplos:
  $0 -f hashes.txt -w wordlists/common-passwords.txt
  $0 -f hashes.txt -w wordlist.txt -a sha256 -t 16 -o resultado.txt
  $0 -f hash_unica.txt -w wordlist.txt -a md5 -s

EOF
    exit 1
}

log_info() { $QUIET || echo -e "${BLUE}[*]${NC} $1"; }
log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "${RED}[x]${NC} $1" >&2; }

parse_args() {
    [[ $# -eq 0 ]] && usage
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f|--hash-file) HASH_FILE="$2"; shift 2 ;;
            -w|--wordlist) WORDLIST="$2"; shift 2 ;;
            -a|--algo) ALGO="$2"; shift 2 ;;
            -t|--threads) THREADS="$2"; shift 2 ;;
            -o|--output) OUTPUT="$2"; shift 2 ;;
            -P|--salt-prefix) SALT_PREFIX="$2"; shift 2 ;;
            -S|--salt-suffix) SALT_SUFFIX="$2"; shift 2 ;;
            -s|--stop-on-all-found) STOP_ON_ALL=true; shift ;;
            -q|--quiet) QUIET=true; shift ;;
            -v|--version) echo "bash-cracker.sh v${VERSION}"; exit 0 ;;
            -h|--help) usage ;;
            *) log_err "Argumento desconhecido: $1"; usage ;;
        esac
    done
}

validate_deps() {
    for cmd in xargs awk grep; do
        command -v "$cmd" &>/dev/null || { log_err "Dependência ausente: $cmd"; exit 1; }
    done
}

hash_cmd_for() {
    case "$1" in
        md5) echo "md5sum" ;;
        sha1) echo "sha1sum" ;;
        sha256) echo "sha256sum" ;;
        sha512) echo "sha512sum" ;;
        *) echo "" ;;
    esac
}

detect_algo_by_len() {
    local len="$1"
    case "$len" in
        32) echo "md5" ;;
        40) echo "sha1" ;;
        64) echo "sha256" ;;
        128) echo "sha512" ;;
        *) echo "" ;;
    esac
}

validate_input() {
    [[ -z "$HASH_FILE" ]] && { log_err "Arquivo de hashes (-f) é obrigatório."; usage; }
    [[ -z "$WORDLIST" ]] && { log_err "Wordlist (-w) é obrigatória."; usage; }
    [[ -f "$HASH_FILE" ]] || { log_err "Arquivo de hashes não encontrado: $HASH_FILE"; exit 1; }
    [[ -f "$WORDLIST" ]] || { log_err "Wordlist não encontrada: $WORDLIST"; exit 1; }
    [[ -s "$WORDLIST" ]] || { log_err "Wordlist vazia: $WORDLIST"; exit 1; }

    if [[ "$ALGO" != "auto" ]]; then
        [[ -z "$(hash_cmd_for "$ALGO")" ]] && { log_err "Algoritmo inválido: $ALGO"; exit 1; }
        command -v "$(hash_cmd_for "$ALGO")" &>/dev/null || {
            log_err "Utilitário $(hash_cmd_for "$ALGO") não encontrado no sistema."
            exit 1
        }
    fi

    if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [[ "$THREADS" -lt 1 ]]; then
        log_err "Threads inválido: $THREADS"
        exit 1
    fi
}

# Carrega hashes normalizando para minúsculas.
# Gera 3 arquivos temporários: alvo (hash), rótulo (user ou hash), algoritmo detectado.
TMP_DIR=""
prepare_targets() {
    TMP_DIR=$(mktemp -d /tmp/ghostcrack.XXXXXX)
    trap 'rm -rf "$TMP_DIR"' EXIT

    local targets_all="${TMP_DIR}/targets_all.tsv"   # algo<TAB>hash<TAB>label
    : > "$targets_all"

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        local label hashval
        if [[ "$line" == *:* ]]; then
            label="${line%%:*}"
            hashval="${line#*:}"
        else
            label="$line"
            hashval="$line"
        fi
        hashval=$(echo -n "$hashval" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')

        local algo="$ALGO"
        if [[ "$ALGO" == "auto" ]]; then
            algo=$(detect_algo_by_len "${#hashval}")
        fi
        [[ -z "$algo" ]] && { log_warn "Hash ignorada (tamanho não reconhecido): $line"; continue; }

        printf "%s\t%s\t%s\n" "$algo" "$hashval" "$label" >> "$targets_all"
    done < "$HASH_FILE"

    echo "$targets_all"
}

# ---------- Worker (executado em paralelo via xargs) ----------
# Recebe: algoritmo, arquivo de alvos (algo\thash\tlabel), salt prefix/suffix
# Lê UMA palavra via stdin argumento posicional.
crack_word() {
    local word="$1"
    local algo="$2"
    local targets_file="$3"
    local salt_prefix="$4"
    local salt_suffix="$5"

    [[ -z "$word" ]] && return

    local candidate="${salt_prefix}${word}${salt_suffix}"
    local hashcmd
    hashcmd=$(hash_cmd_for "$algo")
    [[ -z "$hashcmd" ]] && return

    local digest
    digest=$(printf '%s' "$candidate" | "$hashcmd" | awk '{print $1}')

    local match
    match=$(awk -F'\t' -v d="$digest" -v a="$algo" '$1==a && $2==d {print $3; found=1} END{if(!found) exit 1}' "$targets_file")

    if [[ -n "$match" ]]; then
        while IFS= read -r label; do
            echo "${algo}|${digest}|${label}|${candidate}"
        done <<< "$match"
    fi
}
export -f crack_word
export -f hash_cmd_for

run_for_algo() {
    local algo="$1"
    local targets_file="$2"

    log_info "Testando wordlist contra hashes ${algo^^}..."

    cat "$WORDLIST" | \
        xargs -P "$THREADS" -I {} bash -c \
            'crack_word "$1" "$2" "$3" "$4" "$5"' _ {} "$algo" "$targets_file" "$SALT_PREFIX" "$SALT_SUFFIX"
}

main() {
    parse_args "$@"
    validate_deps
    validate_input

    $QUIET || banner

    local targets_all
    targets_all=$(prepare_targets)

    local total_targets
    total_targets=$(wc -l < "$targets_all" | tr -d ' ')

    if [[ "$total_targets" -eq 0 ]]; then
        log_err "Nenhuma hash válida para processar."
        exit 1
    fi

    local algos_presentes
    algos_presentes=$(awk -F'\t' '{print $1}' "$targets_all" | sort -u)

    log_info "Arquivo de hashes : $HASH_FILE"
    log_info "Hashes a testar   : $total_targets"
    log_info "Algoritmos        : $(echo "$algos_presentes" | tr '\n' ',' | sed 's/,$//')"
    log_info "Wordlist          : $WORDLIST ($(wc -l < "$WORDLIST" | tr -d ' ') linhas)"
    log_info "Threads           : $THREADS"
    [[ -n "$SALT_PREFIX$SALT_SUFFIX" ]] && log_info "Salt: prefix='${SALT_PREFIX}' suffix='${SALT_SUFFIX}'"
    echo ""

    [[ -n "$OUTPUT" ]] && {
        {
            echo "# GhostCrack (bash-cracker.sh) - resultados"
            echo "# Data: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "# Hash file: $HASH_FILE | Wordlist: $WORDLIST"
            echo ""
        } > "$OUTPUT"
    }

    local start_time end_time cracked_count=0
    start_time=$(date +%s)

    local results_file="${TMP_DIR}/results.txt"
    : > "$results_file"

    while IFS= read -r algo; do
        [[ -z "$algo" ]] && continue
        run_for_algo "$algo" "$targets_all" >> "$results_file"
    done <<< "$algos_presentes"

    # Deduplica e exibe resultados
    if [[ -s "$results_file" ]]; then
        sort -u "$results_file" | while IFS='|' read -r algo digest label plaintext; do
            echo -e "${GREEN}[+] CRACKED${NC} [${algo}] ${label}:${digest} => ${BOLD}${plaintext}${NC}"
            [[ -n "$OUTPUT" ]] && echo "${algo}:${label}:${digest}:${plaintext}" >> "$OUTPUT"
        done
        cracked_count=$(sort -u "$results_file" | wc -l | tr -d ' ')
    fi

    end_time=$(date +%s)
    local elapsed=$((end_time - start_time))

    echo ""
    echo -e "${BOLD}Resumo:${NC}"
    echo "  Tempo total      : ${elapsed}s"
    echo -e "  Hashes quebradas: ${GREEN}${cracked_count}${NC} / ${total_targets}"
    echo -e "  Não quebradas   : ${RED}$((total_targets - cracked_count))${NC}"

    [[ -n "$OUTPUT" ]] && log_ok "Resultado salvo em: $OUTPUT"

    [[ "$cracked_count" -lt "$total_targets" ]] && exit 2
    exit 0
}

main "$@"
