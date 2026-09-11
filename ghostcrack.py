#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 GhostCrack - Hash Cracker / Encoder / Decoder profissional
 Autores : pablocybersec & prof. 0xGhostSec
 Descrição:
   Ferramenta de quebra de hashes por ataque de dicionário (wordlist),
   com suporte a MD5, SHA1, SHA256 e SHA512, detecção automática de
   algoritmo, mutações básicas de candidatos, multiprocessamento real
   e geração/decodificação de hashes (incluindo Base64).

 AVISO LEGAL / ÉTICO:
   Use esta ferramenta SOMENTE em hashes que você tem autorização
   para testar (labs próprios, CTFs, hashes que você mesmo gerou
   para fins educacionais). Quebrar credenciais de terceiros sem
   autorização é crime na maioria das jurisdições.
=====================================================================
"""

import argparse
import base64
import binascii
import hashlib
import multiprocessing as mp
import os
import sys
import time
from functools import partial

VERSION = "1.0"

# ---------------------------------------------------------------
# Cores para terminal
# ---------------------------------------------------------------
class C:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    BOLD = "\033[1m"
    END = "\033[0m"


BANNER = rf"""{C.CYAN}{C.BOLD}
   ______ __              __   ______                __
  / ____// /_   ____   ___/ /_ / ____/_____ ____ _ _____ / /__
 / / __ / __ \ / __ \ / ___// // /    / ___// __ `// ___// //_/
/ /_/ // / / // /_/ /(__  )/ /_/ /___ / /   / /_/ // /__ / ,<
\____//_/ /_/ \____/____/  \____/\____//_/    \__,_/ \___//_/|_|
{C.END}{C.BOLD}      GhostCrack v{VERSION} - by pablocybersec & prof. 0xGhostSec{C.END}
{C.CYAN}   Hash Cracker / Encoder / Decoder - Python Engine{C.END}
"""

# Algoritmos suportados e o tamanho (em hex chars) da hash resultante
HASH_LENGTHS = {
    32: "md5",
    40: "sha1",
    64: "sha256",
    128: "sha512",
}

ALGO_FUNCS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def compute_hash(algo: str, data: bytes) -> str:
    return ALGO_FUNCS[algo](data).hexdigest()


def identify_algo(hash_str: str):
    """Tenta identificar o algoritmo pelo tamanho da hash em hexadecimal."""
    h = hash_str.strip().lower()
    if not all(c in "0123456789abcdef" for c in h):
        return None
    return HASH_LENGTHS.get(len(h))


# ---------------------------------------------------------------
# Leitura do arquivo de hashes
# Formatos aceitos por linha:
#   <hash>
#   <usuario>:<hash>
#   linhas vazias e iniciadas com # são ignoradas
# ---------------------------------------------------------------
def load_hashes(path):
    targets_by_algo = {}   # algo -> { hash_lower: [rótulos] }
    forced_unknown = []    # hashes que não bateram com nenhum tamanho conhecido
    total = 0

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if ":" in line:
                label, h = line.split(":", 1)
            else:
                label, h = line, line

            h = h.strip().lower()
            label = label.strip()

            algo = identify_algo(h)
            total += 1
            if algo is None:
                forced_unknown.append((label, h))
                continue

            targets_by_algo.setdefault(algo, {}).setdefault(h, []).append(label)

    return targets_by_algo, forced_unknown, total


# ---------------------------------------------------------------
# Mutações básicas de candidato (modo --mutate)
# ---------------------------------------------------------------
def mutate_candidate(word: str):
    variants = {word, word.lower(), word.upper(), word.capitalize()}
    suffixes = ["", "1", "12", "123", "!", "2024", "2025", "2026"]
    out = set()
    for v in variants:
        for s in suffixes:
            out.add(v + s)
    return out


# ---------------------------------------------------------------
# Worker de processo: recebe um chunk de candidatos e os algoritmos
# que precisam ser testados; usa variáveis globais inicializadas
# por _init_worker para evitar re-serializar os alvos a cada tarefa.
# ---------------------------------------------------------------
_G_TARGETS = None
_G_ALGOS = None
_G_SALT_PREFIX = None
_G_SALT_SUFFIX = None
_G_MUTATE = None


def _init_worker(targets_by_algo, algos, salt_prefix, salt_suffix, mutate):
    global _G_TARGETS, _G_ALGOS, _G_SALT_PREFIX, _G_SALT_SUFFIX, _G_MUTATE
    _G_TARGETS = targets_by_algo
    _G_ALGOS = algos
    _G_SALT_PREFIX = salt_prefix or ""
    _G_SALT_SUFFIX = salt_suffix or ""
    _G_MUTATE = mutate


def _process_chunk(words):
    found = []  # lista de (algo, hash, label, plaintext)
    for word in words:
        word = word.rstrip("\n\r")
        if not word:
            continue

        candidates = mutate_candidate(word) if _G_MUTATE else {word}

        for cand in candidates:
            salted = f"{_G_SALT_PREFIX}{cand}{_G_SALT_SUFFIX}"
            data = salted.encode("utf-8", errors="ignore")
            for algo in _G_ALGOS:
                digest = compute_hash(algo, data)
                bucket = _G_TARGETS.get(algo)
                if bucket and digest in bucket:
                    for label in bucket[digest]:
                        found.append((algo, digest, label, cand))
    return found


def chunked(iterable, size):
    chunk = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


# ---------------------------------------------------------------
# Modo CRACK (ataque de dicionário)
# ---------------------------------------------------------------
def cmd_crack(args):
    if not args.quiet:
        print(BANNER)

    if not os.path.isfile(args.hash_file):
        eprint(f"{C.RED}[x] Arquivo de hashes não encontrado: {args.hash_file}{C.END}")
        sys.exit(1)
    if not os.path.isfile(args.wordlist):
        eprint(f"{C.RED}[x] Wordlist não encontrada: {args.wordlist}{C.END}")
        sys.exit(1)

    targets_by_algo, unknown, total = load_hashes(args.hash_file)

    if args.algo != "auto":
        # força um único algoritmo para TODAS as hashes do arquivo
        merged = {}
        for algo, bucket in targets_by_algo.items():
            for h, labels in bucket.items():
                merged.setdefault(h, []).extend(labels)
        for label, h in unknown:
            merged.setdefault(h, []).append(label)
        targets_by_algo = {args.algo: merged}
        unknown = []

    algos_presentes = list(targets_by_algo.keys())

    if not algos_presentes:
        eprint(f"{C.RED}[x] Nenhuma hash válida encontrada em {args.hash_file}{C.END}")
        sys.exit(1)

    n_targets = sum(len(b) for b in targets_by_algo.values())

    print(f"{C.BLUE}[*]{C.END} Arquivo de hashes : {args.hash_file}")
    print(f"{C.BLUE}[*]{C.END} Total de linhas   : {total}")
    print(f"{C.BLUE}[*]{C.END} Hashes únicas     : {n_targets}")
    print(f"{C.BLUE}[*]{C.END} Algoritmos        : {', '.join(algos_presentes)}")
    if unknown:
        print(f"{C.YELLOW}[!]{C.END} {len(unknown)} hash(es) com tamanho não reconhecido (ignoradas)")
    print(f"{C.BLUE}[*]{C.END} Wordlist          : {args.wordlist}")
    print(f"{C.BLUE}[*]{C.END} Processos         : {args.workers}")
    print(f"{C.BLUE}[*]{C.END} Mutação           : {'ativada' if args.mutate else 'desativada'}")
    if args.salt_prefix or args.salt_suffix:
        print(f"{C.BLUE}[*]{C.END} Salt              : prefix='{args.salt_prefix or ''}' suffix='{args.salt_suffix or ''}'")
    print("")

    cracked = {}   # (algo, hash) -> plaintext
    labels_map = {}
    for algo, bucket in targets_by_algo.items():
        for h, labels in bucket.items():
            labels_map[(algo, h)] = labels

    start = time.time()
    tried = 0
    last_report = start

    def word_generator():
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as wf:
            for line in wf:
                yield line.rstrip("\n\r")

    ctx = mp.get_context("fork") if hasattr(mp, "get_context") and os.name != "nt" else mp
    with ctx.Pool(
        processes=args.workers,
        initializer=_init_worker,
        initargs=(targets_by_algo, algos_presentes, args.salt_prefix, args.salt_suffix, args.mutate),
    ) as pool:
        chunk_iter = chunked(word_generator(), args.chunk_size)
        result_iter = pool.imap_unordered(_process_chunk, chunk_iter)

        for chunk_found in result_iter:
            tried += args.chunk_size

            for algo, digest, label, plaintext in chunk_found:
                key = (algo, digest)
                if key not in cracked:
                    cracked[key] = plaintext
                    print(f"{C.GREEN}[+] CRACKED{C.END} [{algo}] {label}:{digest} => {C.BOLD}{plaintext}{C.END}")

            now = time.time()
            if not args.quiet and (now - last_report) > 1.0:
                elapsed = now - start
                speed = tried / elapsed if elapsed > 0 else 0
                sys.stdout.write(
                    f"\r{C.CYAN}[~] Testadas: ~{tried:,} | Velocidade: {speed:,.0f}/s | "
                    f"Encontradas: {len(cracked)}/{n_targets}{C.END}   "
                )
                sys.stdout.flush()
                last_report = now

            if args.stop_when_all_found and len(cracked) >= n_targets:
                pool.terminate()
                break

    if not args.quiet:
        sys.stdout.write("\n")

    elapsed = time.time() - start
    print("")
    print(f"{C.BOLD}Resumo:{C.END}")
    print(f"  Tempo total      : {elapsed:.2f}s")
    print(f"  Hashes quebradas : {C.GREEN}{len(cracked)}{C.END} / {n_targets}")
    print(f"  Não quebradas    : {C.RED}{n_targets - len(cracked)}{C.END}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            out.write("# GhostCrack - resultados\n")
            out.write(f"# Arquivo de hashes: {args.hash_file}\n")
            out.write(f"# Wordlist: {args.wordlist}\n\n")
            for (algo, digest), plaintext in cracked.items():
                for label in labels_map.get((algo, digest), [digest]):
                    out.write(f"{algo}:{label}:{digest}:{plaintext}\n")
        print(f"\n{C.GREEN}[+]{C.END} Resultado salvo em: {args.output}")

    not_cracked = n_targets - len(cracked)
    sys.exit(0 if not_cracked == 0 else 2)


# ---------------------------------------------------------------
# Modo ENCODE
# ---------------------------------------------------------------
def cmd_encode(args):
    if args.text is None and args.file is None:
        eprint(f"{C.RED}[x] Informe --text ou --file{C.END}")
        sys.exit(1)

    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
    else:
        data = args.text.encode("utf-8")

    algos = ALGO_FUNCS.keys() if args.algo == "all" else [args.algo] if args.algo != "base64" else []

    print(f"{C.BOLD}Entrada:{C.END} {args.text if args.text is not None else f'<arquivo: {args.file}>'}")
    print("")

    if args.algo in ("base64", "all"):
        b64 = base64.b64encode(data).decode("ascii")
        print(f"  {C.CYAN}base64{C.END} : {b64}")

    for algo in algos:
        digest = ALGO_FUNCS[algo](data).hexdigest()
        print(f"  {C.CYAN}{algo:<7}{C.END}: {digest}")


# ---------------------------------------------------------------
# Modo DECODE (somente reversível: base64 / hex)
# ---------------------------------------------------------------
def cmd_decode(args):
    if args.text is None and args.file is None:
        eprint(f"{C.RED}[x] Informe --text ou --file{C.END}")
        sys.exit(1)

    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            raw = f.read().strip()
    else:
        raw = args.text.strip()

    try:
        if args.algo == "base64":
            decoded = base64.b64decode(raw)
        elif args.algo == "hex":
            decoded = binascii.unhexlify(raw)
        else:
            eprint(f"{C.RED}[x] Algoritmo de decodificação inválido: {args.algo}{C.END}")
            sys.exit(1)
    except Exception as e:
        eprint(f"{C.RED}[x] Falha ao decodificar: {e}{C.END}")
        sys.exit(1)

    try:
        text = decoded.decode("utf-8")
        print(f"{C.GREEN}[+] Decodificado (utf-8):{C.END} {text}")
    except UnicodeDecodeError:
        print(f"{C.YELLOW}[!] Dados binários (não é texto utf-8). Bytes:{C.END}")
        print(decoded)


# ---------------------------------------------------------------
# Modo IDENTIFY
# ---------------------------------------------------------------
def cmd_identify(args):
    h = args.hash.strip()
    algo = identify_algo(h)
    if algo:
        print(f"{C.GREEN}[+]{C.END} Provável algoritmo: {C.BOLD}{algo}{C.END} (tamanho: {len(h)} hex chars)")
    else:
        print(f"{C.YELLOW}[!]{C.END} Não foi possível identificar o algoritmo pelo tamanho ({len(h)} chars).")
        print("    Tamanhos conhecidos: 32=MD5, 40=SHA1, 64=SHA256, 128=SHA512")


# ---------------------------------------------------------------
# CLI
# ---------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="ghostcrack.py",
        description="GhostCrack - Hash Cracker / Encoder / Decoder (by pablocybersec & prof. 0xGhostSec)",
    )
    p.add_argument("-v", "--version", action="version", version=f"GhostCrack v{VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    # crack
    pc = sub.add_parser("crack", help="Quebra hashes via ataque de dicionário (wordlist)")
    pc.add_argument("-f", "--hash-file", required=True, help="Arquivo com hash(es). Formatos: 'hash' ou 'usuario:hash' por linha")
    pc.add_argument("-w", "--wordlist", required=True, help="Caminho da wordlist")
    pc.add_argument(
        "-a", "--algo", default="auto",
        choices=["auto", "md5", "sha1", "sha256", "sha512"],
        help="Algoritmo (padrão: auto-detecta pelo tamanho da hash)",
    )
    pc.add_argument("-o", "--output", help="Arquivo para salvar resultados (algo:label:hash:plaintext)")
    pc.add_argument("-t", "--workers", type=int, default=max(1, os.cpu_count() or 1), help="Nº de processos paralelos")
    pc.add_argument("--chunk-size", type=int, default=2000, help="Tamanho do lote enviado a cada processo (padrão 2000)")
    pc.add_argument("--mutate", action="store_true", help="Ativa mutações básicas (maiúsc/minúsc, sufixos numéricos)")
    pc.add_argument("--salt-prefix", default="", help="Prefixo de salt aplicado antes do candidato")
    pc.add_argument("--salt-suffix", default="", help="Sufixo de salt aplicado depois do candidato")
    pc.add_argument("--stop-when-all-found", action="store_true", help="Encerra assim que todas as hashes forem quebradas")
    pc.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso (sem banner/progresso)")
    pc.set_defaults(func=cmd_crack)

    # encode
    pe = sub.add_parser("encode", help="Gera hash/encoding de um texto ou arquivo")
    g = pe.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", help="Texto a ser codificado/hasheado")
    g.add_argument("--file", help="Arquivo cujo conteúdo será codificado/hasheado")
    pe.add_argument(
        "-a", "--algo", default="all",
        choices=["md5", "sha1", "sha256", "sha512", "base64", "all"],
        help="Algoritmo de saída (padrão: all)",
    )
    pe.set_defaults(func=cmd_encode)

    # decode
    pd = sub.add_parser("decode", help="Decodifica base64/hex (hashes reais NÃO podem ser 'decodificadas', use 'crack')")
    g2 = pd.add_mutually_exclusive_group(required=True)
    g2.add_argument("--text", help="Texto a ser decodificado")
    g2.add_argument("--file", help="Arquivo cujo conteúdo será decodificado")
    pd.add_argument("-a", "--algo", default="base64", choices=["base64", "hex"])
    pd.set_defaults(func=cmd_decode)

    # identify
    pi = sub.add_parser("identify", help="Tenta identificar o algoritmo de uma hash pelo tamanho")
    pi.add_argument("hash", help="String da hash")
    pi.set_defaults(func=cmd_identify)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
