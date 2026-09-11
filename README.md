# GhostCrack 🔓

Ferramenta modular de cracking de hashes e análise de senhas, criada por **pablocybersec** & **prof. 0xGhostSec**.

O **GhostCrack** foi desenvolvido para fins educacionais e de auditoria de segurança, oferecendo um motor robusto em Python 3 e uma alternativa de contingência 100% em Bash puro para ambientes restritos.

> ⚠️ **Uso ético e legal.** Use esta ferramenta apenas em sistemas que você possui ou tem autorização explícita (por escrito) para testar. Testes de força bruta sem autorização são ilegais.

---

## Arquitetura do Projeto

O projeto é composto por um ecossistema inteligente de scripts para garantir flexibilidade em diferentes cenários de laboratório e pós-exploração:

- **`GhostCrack.sh`**: Launcher oficial em Bash. Verifica dependências, localiza automaticamente o interpretador Python 3 e repassa os argumentos com segurança para o motor principal. Se o Python não estiver disponível, sugere o uso da versão alternativa.
- **`ghostcrack.py`**: O motor principal da ferramenta, escrito em Python, responsável pelas operações robustas de cracking e lógica avançada.
- **`bash-cracker.sh`**: Alternativa 100% em Bash puro, ideal para containers Docker enxutos ou ambientes de pós-exploração onde o Python não está instalado.
- **`encode-decode.sh`**: Utilitário rápido para codificação e decodificação de strings e dados auxiliares.

---

## Requisitos

- **Bash 4+**
- **Python 3.x** (Opcional, mas necessário para o motor principal `ghostcrack.py`)
- Utilitários standard do ecossistema Linux (`coreutils`)

---

## Instalação

Clone o repositório e conceda permissão de execução aos scripts:

```bash
git clone https://github.com/Deepaudit/GhostCrack.git
cd ghost-crack
chmod +x GhostCrack.sh bash-cracker.sh encode-decode.sh
