# Relatório Técnico — Crypto Delphi (UTCTF 2021)

> Versão convertida para README a partir do relatório em PDF. Fonte original: Relatório_Desafio_Crito_Delphi.pdf. :contentReference[oaicite:1]{index=1}

## Resumo
Exploração prática de **padding oracle** em um serviço que utiliza **AES-CBC + PKCS#7**.  
Resultado prático: recuperação da flag `utflag{oracle_padded_oops}`.  
O documento traz: objetivos, estratégia de exploração, exploit em Python (comentado), análise de impacto, mitigação alinhada ao OWASP e recomendações operacionais.

---

## Sumário
1. [Introdução](#introdução)  
2. [Objetivo do desafio](#objetivo-do-desafio)  
3. [Arquivos e writeups consultados](#arquivos-e-writeups-consultados)  
4. [Conceitos técnicos (resumo prático)](#conceitos-técnicos-resumo-prático)  
5. [Comportamento do serviço vulnerável](#comportamento-do-serviço-vulnerável)  
6. [Estratégia de exploração — passo a passo](#estratégia-de-exploração---passo-a-passo)  
7. [Exploit (Python) — código comentado](#exploit-python---código-comentado)  
8. [Complexidade e custo (número de requisições)](#complexidade-e-custo-número-de-requisições)  
9. [Análise de impacto](#análise-de-impacto)  
10. [Mitigações (mapeadas ao OWASP A02)](#mitigações-mapeadas-ao-owasp-a02)  
11. [Detecção e monitoramento](#detecção-e-monitoramento)  
12. [Lições e recomendações finais](#lições-e-recomendações-finais)  
13. [Referências](#referências)

---

## 1 — Introdução
O desafio *Delphi* (UTCTF 2021) apresenta um serviço que recebe ciphertexts e tenta descriptografá-los usando AES-CBC com padding PKCS#7. O serviço responde de forma distinta quando o padding é inválido, caracterizando um **padding oracle** — uma falha que permite recuperar plaintexts sem conhecer a chave. A flag obtida no CTF foi:  
**`utflag{oracle_padded_oops}`**.

---

## 2 — Objetivo do desafio
- Explorar o padding oracle para recuperar a flag presente no plaintext.  
- Demonstrar como diferenças aparentemente pequenas nas mensagens/erros podem comprometer totalmente a confidencialidade.

---

## 3 — Arquivos e writeups consultados
- Repositório com solução: `utisss/UTCTF-21/crypto-delphi`.  
- Writeup alternativo: `cscosu/ctf-writeups/2021/utctf/Delphi`.  
- Documentação e guias sobre padding oracle (Vaudenay, Cryptopals, NCC Group).  
- OWASP — *A02: Cryptographic Failures* e *OWASP WSTG — Testing for Padding Oracle*.

---

## 4 — Conceitos técnicos (resumo prático)
- **AES-CBC**: cifra blocos de 16 bytes; P_i = Dec_k(C_i) ⊕ C_{i-1} (IV para o primeiro bloco).  
- **PKCS#7**: padding por bytes cujo valor indica o número de bytes de preenchimento (ex.: `0x04 0x04 0x04 0x04`).  
- **Padding oracle**: quando o servidor distingue (direta/indiretamente) entre padding válido e inválido, permitindo um atacante inferir bytes do *intermediate value* `Dec_k(C_i)` e reconstruir o plaintext.

---

## 5 — Comportamento do serviço vulnerável
Observações práticas (extraídas dos writeups / análise do serviço):
- O serviço diferencia respostas para `padding invalid` vs. outros erros (ou por timing/comportamento).  
- Endpoint típico: recebe ciphertext em hex/base64 e retorna uma linha/texto indicando o resultado da decriptação (ex.: `"Invalid challenge..."`, `"Decryption failed."`, `"Authorization verified."`).

---

## 6 — Estratégia de exploração — passo a passo (resumido)
1. Capturar ciphertext alvo: IV + C0, C1, ...  
2. Para cada bloco C_i (i ≥ 1), manipular bytes de C_{i-1} e enviar (IV,..., C'_{i-1}, C_i, ...).  
3. Usar o oracle: ajustar C'_{i-1} até que o servidor reporte padding válido → revela informações sobre `Dec_k(C_i)`.  
4. Repetir byte a byte (do último para o primeiro) para recuperar P_i = Dec_k(C_i) ⊕ C_{i-1}.  
5. Repetir para todos os blocos até recuperar o plaintext (flag).

---

## 7 — Exploit (Python) — código comentado
> **Aviso**: código educacional para uso em CTFs/laboratórios. Não executar contra alvos sem autorização.

```python
#!/usr/bin/env python3
# Simplified excerpt do solver padding-oracle (ver relatório para versão completa)
import binascii, sys
from pwn import remote   # pip install pwntools

HOST = "crypto.utctf.live"
PORT = 9003
BLOCK_SIZE = 16

def hex_to_bytes(h): return binascii.unhexlify(h.strip())

def query_server(sock, payload_bytes):
    """
    Envia payload hex ao servidor e retorna True se padding válido.
    Ajuste a heurística de parsing da resposta ao comportamento real do serviço.
    """
    sock.sendline(payload_bytes.hex().encode())
    resp = sock.recvline(timeout=5).decode(errors='ignore').lower()
    if "invalid padding" in resp or "pad error" in resp or "padding error" in resp:
        return False
    if "success" in resp or "ok" in resp or "valid" in resp:
        return True
    return ("decrypt failure" not in resp) and ("error" not in resp)

# Funções auxiliares omitidas por brevidade (ver o relatório para versão completa).
