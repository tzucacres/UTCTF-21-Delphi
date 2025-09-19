#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------
# Solver de Padding-Oracle para AES-CBC/PKCS#7 usado no desafio "Delphi"
# Estratégia:
#   - O serviço remoto (oracle) retorna três tipos de mensagens ao receber
#     um "token" em hexadecimal:
#         * BAD  -> "Decryption failed."      (falha genérica)
#         * PAD  -> "Invalid challenge..."    (padding válido, mas challenge inválido)
#         * OK   -> "Authorization verified." (token válido, autenticação aceita)
#   - Num clássico ataque de padding-oracle, um retorno que distingue
#     "padding válido" de "padding inválido" permite recuperar o "intermediate
#     value" J = Dec_k(C) bloco a bloco. Com J recuperado, manipulamos XORs
#     para forjar IV/C1/C2/... que decifram em um plaintext desejado.
#   - Este solver é otimizado para:
#       (1) executar *batches* de 256 palpites por byte (economizando ciclos);
#       (2) recuperar J de um bloco "C_last" em uma única conexão (há ~29 ciclos);
#       (3) encadear três conexões no total para montar um token válido.
#   - Nomenclatura:
#       * Jx = Dec_k(Cx)  (valor intermediário do CBC)
#       * B1|B2 = "challenge" de 32 bytes que o servidor manda ao conectar
#       * PAD16 = bloco de 16 bytes 0x10 (padding completo)
#
# Observação didática:
#   - O CBC decripta bloco a bloco: P_i = Dec_k(C_i) ⊕ C_{i-1} (ou IV para i=0).
#   - Se controlamos C_{i-1}, conseguimos forçar o padding de P_i a ser válido
#     e, com isso, inferir bytes de Dec_k(C_i) (o "J").
#   - A cada byte resolvido, ajustamos os anteriores para "pad" consistente.
# ---------------------------------------------------------------------------

import argparse, os, socket, binascii

# Assinaturas de strings que o oracle devolve (em bytes), usadas para classificar respostas:
PROMPT = b"Please submit authorization token."
BAD    = b"Decryption failed."
PAD    = b"Invalid challenge provided."
OK     = b"Authorization verified."

def read_line(rf):
    """
    Lê exatamente uma linha do arquivo/socket encapsulado em 'rf'.
    Se não vier nada (EOF), lança exceção para que o fluxo trate desconexões.
    """
    line = rf.readline()
    if not line:
        raise EOFError("EOF do oracle")
    return line

def read_until_challenge(rf):
    """
    Ao conectar, o serviço envia várias linhas até publicar a 'Challenge: <hex>'.
    Esta função consome as linhas até encontrar a challenge e a retorna em bytes.
    """
    chall = None
    while True:
        line = read_line(rf)
        if line.startswith(b"Challenge: "):
            h = line.split(b":",1)[1].strip()
            chall = bytes.fromhex(h.decode())
            break
    return chall

def drain_until_prompt(rf):
    """
    Após enviar um batch de tentativas, o oracle imprime várias linhas,
    incluindo contadores/ruídos. Esta função descarta tudo até detectar
    o PROMPT ('Please submit authorization token.').
    Serve para "ressincronizar" a leitura entre ciclos.
    """
    # Lê até ver o prompt. Ignora contadores/ruídos entre ciclos.
    while True:
        line = read_line(rf)
        if PROMPT in line:
            return

def classify_line(line):
    """
    Classifica uma linha de resposta do oracle:
      - 'bad' se for falha genérica de descriptografia (padding inválido).
      - 'pad' se for 'Invalid challenge...' (padding VÁLIDO; estrutura OK).
      - 'ok'  se for 'Authorization verified' (token aceito).
    Retorna None para linhas irrelevantes/ruído.
    """
    s = line.strip()
    if s == BAD: return "bad"
    if s == PAD: return "pad"
    if s.startswith(OK): return "ok"
    return None  # ruído

def send_batch_and_read_results(sock, rf, hex_lines, expected):
    """
    Envia um *lote* (batch) com N linhas hexadecimais (cada uma é um token a testar),
    e em seguida coleta exatamente N classificações ('bad'/'pad'/'ok'), ignorando ruídos.
    - 'sock' é o socket aberto para enviar os bytes (mais eficiente que file.write).
    - 'rf' é o file-like (buffered reader) para ler as respostas linha a linha.
    - 'hex_lines' é a lista de strings hex (sem '\n').
    - 'expected' é o número de respostas úteis esperadas (igual a len(hex_lines)).
    """
    # Envia N linhas de HEX e lê exatamente N classificações (ignora ruídos).
    payload = ("\n".join(hex_lines) + "\n").encode()
    sock.sendall(payload)
    results = []
    while len(results) < expected:
        cls = classify_line(read_line(rf))
        if cls in ("bad","pad","ok"):
            results.append(cls)
    return results

def recover_intermediate_for_block(host, port, C_last):
    """
    Recupera o 'intermediate value' do bloco alvo:
        J = Dec_k(C_last)
    usando padding-oracle.

    Como?
      - Abrimos *uma conexão* ao oracle.
      - Criamos um bloco anterior "D" (controlado por nós), pois no CBC:
            P = Dec_k(C_last) ⊕ D
        Se acertarmos D de modo que P tenha padding válido, o oracle responde 'PAD'.
      - Fazemos brute force byte a byte (de trás para frente), ajustando D
        para simular um padding de tamanho 'pad = 1, 2, ..., 16'.
      - Otimização: em vez de 256 tentativas separadas com ida/volta, enviamos
        as 256 linhas (todas as possibilidades para o byte corrente) em um *único batch*.
      - Para cada byte, coletamos 256 respostas e escolhemos a primeira que
        seja 'pad' ou 'ok' (ambas indicam padding válido).

    Notas operacionais:
      - O serviço dá ~29 ciclos por conexão; recuperar um bloco consome 16 ciclos
        (um por byte), então cabe com folga em uma única conexão.
      - Ao fim de cada ciclo, drenamos até o PROMPT para manter sincronismo.

    Parâmetros:
      - host, port: endereço do oracle.
      - C_last: bloco de 16 bytes que queremos "quebrar" (em geral, um bloco
        que nós escolhemos ou que vem do protocolo).

    Retorno:
      - bytes(J), onde J = Dec_k(C_last).
    """
    with socket.create_connection((host, port), timeout=30) as s:
        rf = s.makefile("rb", buffering=0)
        chall = read_until_challenge(rf)  # só para sincronizar; valor não importa aqui
        drain_until_prompt(rf)

        D = bytearray(16)   # bloco 'anterior' controlado (será enviado antes de C_last)
        J = bytearray(16)   # armazenará J = Dec_k(C_last)

        for idx in range(15, -1, -1):
            pad = 16 - idx
            # Para bytes já resolvidos, ajusta D[j] para que P[j] = pad (padding consistente)
            for j in range(15, idx, -1):
                D[j] = J[j] ^ pad

            # Prepara as 256 tentativas para o byte atual (em um único ciclo)
            lines = []
            base = D[:]
            for g in range(256):
                base[idx] = g
                payload = bytes(base) + C_last  # Envia D' || C_last
                lines.append(payload.hex())

            # Envia o batch (256 linhas) e lê as 256 classificações
            results = send_batch_and_read_results(s, rf, lines, expected=256)

            # Procura a primeira resposta que indique padding válido ('pad' ou 'ok')
            found = None
            for g, cls in enumerate(results):
                if cls in ("pad","ok"):
                    found = g
                    break
            if found is None:
                # Em condições normais, sempre haverá pelo menos um g que satisfaz o padding
                raise RuntimeError(f"Nenhum padding válido no byte {idx}")

            # A relação fundamental:
            #   Se base[idx] = g produz P[idx] = pad,
            #   então (J[idx] ⊕ g) == pad  =>  J[idx] = g ⊕ pad
            J[idx] = found ^ pad
            D[idx] = found  # opcional, meramente para manter coerência visual

            # Drena até o prompt do próximo ciclo, mantendo a conexão "em dia"
            drain_until_prompt(rf)

        return bytes(J)

def forge_and_submit(host, port):
    """
    Encadeia as três etapas para forjar um token final válido:

    Passo 1: Escolhe um C3 aleatório e recupera J3 = Dec_k(C3)
             => Em posse de J3, podemos fabricar C2 = J3 ⊕ (0x10 * 16) para que,
                ao decifrar C2, o padding final seja 0x10...0x10 (PKCS#7 completo).
                Isso garante estrutura correta para a etapa seguinte.

    Passo 2: Recupera J2 = Dec_k(C2) do bloco recém-fabricado.

    Passo 3: Abre nova conexão, recebe o challenge B1|B2 (32 bytes).
             Queremos montar um token IV|C1|C2|C3 que autentique.
             - Definimos C1 = J2 ⊕ B2  => ao decifrar C1, obteremos P1 = J1 ⊕ B1,
               e ajustando IV = J1 ⊕ B1 faremos P0 correto para o protocolo.
             - Para achar IV, precisamos primeiro recuperar J1 = Dec_k(C1) (padding-oracle de C1).
             - Com J1 em mãos: IV = J1 ⊕ B1.
             - Token final: IV|C1|C2|C3. Enviamos em uma linha HEX e lemos a flag.

    Observações:
      - Reutilizamos a MESMA conexão do Passo 3 para recuperar J1 (16 ciclos),
        pois após o challenge o serviço permite enviar múltiplos testes até novo prompt.
      - 'pad' e 'ok' são indistintos para o propósito de "padding válido"; 'ok' pode
        aparecer ao acaso durante o brute-force, mas não atrapalha a inferência.
    """
    # Passo 1: escolha C3 e recupere J3 em conexão A
    C3 = os.urandom(16)
    J3 = recover_intermediate_for_block(host, port, C3)
    PAD16 = bytes([16])*16
    C2 = bytes(x ^ y for x,y in zip(J3, PAD16))   # C2 = J3 ⊕ 0x10*16

    # Passo 2: recupere J2 = Dec(C2) em conexão B (mesma técnica do passo 1)
    J2 = recover_intermediate_for_block(host, port, C2)

    # Passo 3 (final): conectar, pegar challenge (B1|B2), recuperar J1 para C1 = J2 ⊕ B2,
    # montar IV = J1 ⊕ B1 e enviar IV|C1|C2|C3
    with socket.create_connection((host, port), timeout=30) as s:
        rf = s.makefile("rb", buffering=0)
        chall = read_until_challenge(rf)
        assert len(chall) == 32
        B1, B2 = chall[:16], chall[16:]
        drain_until_prompt(rf)

        # Se C1 = J2 ⊕ B2, então J1 = Dec(C1) será usado para construir IV.
        C1 = bytes(x ^ y for x,y in zip(J2, B2))

        # Recuperar J1 para C1 nesta mesma conexão (16 ciclos, um por byte).
        D = bytearray(16)
        J1 = bytearray(16)
        for idx in range(15, -1, -1):
            pad = 16 - idx
            for j in range(15, idx, -1):
                D[j] = J1[j] ^ pad
            lines = []
            base = D[:]
            for g in range(256):
                base[idx] = g
                lines.append((bytes(base)+C1).hex())
            results = send_batch_and_read_results(s, rf, lines, expected=256)
            found = None
            for g, cls in enumerate(results):
                if cls in ("pad","ok"):
                    found = g
                    break
            if found is None:
                raise RuntimeError(f"Nenhum padding válido no byte {idx} (J1)")
            J1[idx] = found ^ pad
            D[idx] = found
            drain_until_prompt(rf)

        # Com J1 e B1, o IV que fará P0 correto é IV = J1 ⊕ B1
        IV = bytes(x ^ y for x,y in zip(J1, B1))
        token = IV + C1 + C2 + C3

        # Envia o token (uma única linha em HEX) para autenticar e, em geral, obter a flag.
        s.sendall(token.hex().encode() + b"\n")

        # Lê algumas linhas finais (o serviço pode imprimir status/flag).
        # Não classificamos aqui; apenas repassamos ao stdout.
        try:
            for _ in range(6):
                line = read_line(rf)
                print(line.decode("utf-8","replace").rstrip())
        except EOFError:
            pass

def main():
    """
    Ponto de entrada do script.
      - Argumentos opcionais: host (padrão 'oracle'), port (padrão 4356).
      - Encaminha para forge_and_submit(), que conduz as três etapas descritas.
    """
    ap = argparse.ArgumentParser(description="Padding-Oracle solver para AES-256-CBC/PKCS7 (3 conexões, batches por byte).")
    ap.add_argument("host", nargs="?", default="oracle")
    ap.add_argument("port", nargs="?", type=int, default=4356)
    args = ap.parse_args()
    forge_and_submit(args.host, args.port)

if __name__ == "__main__":
    main()
