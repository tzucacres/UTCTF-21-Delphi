from pathlib import Path

p = Path("/app/solve_delphi.py")
s = p.read_text()

# Substitui a linha de log do imm
s = s.replace(
    'log.info(f"[+] imm[{15 - rnd}] = {imm_byte:02x}")',
    'print(f"[+] byte {15 - rnd:02d} = {imm_byte:02x}", flush=True)'
)

# Adiciona log ao início de forge_block
s = s.replace(
    "def forge_block(io, desired_plain, next_ct):\n    imms = find_immediate_state(io, next_ct)",
    "def forge_block(io, desired_plain, next_ct):\n    print(\"[*] Forge block contra next_ct (16 bytes)…\", flush=True)\n    imms = find_immediate_state(io, next_ct)"
)

# Adiciona log quando fecha bloco
s = s.replace(
    "return bytes([a ^ b for a, b in zip(imms, desired_plain)])",
    "res = bytes([a ^ b for a, b in zip(imms, desired_plain)])\n    print(\"[*] Bloco forjado.\", flush=True)\n    return res"
)

p.write_text(s)
print("Progresso ativado.")
