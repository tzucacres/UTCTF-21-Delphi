import os, binascii, sys, socket, threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

KEY = os.urandom(32)

BANNER = (b"Welcome to the secure flag vault.\n"
          b"Only authorized users can retrieve the flag.\n"
          b"Just encrypt the following challenge in bytes with the secret key.\n"
          b"Use AES-256-CBC with PKCS7 padding. The first 16 bytes should be the IV.\n"
          b"Submit it in hex encoded form.\n"
          b"For security reasons, only 12289 tries are permitted.\n")

def safe_send(conn, data):
    try:
        conn.sendall(data)
        return True
    except (BrokenPipeError, ConnectionResetError, OSError):
        return False

def recv_until_newline(conn, buf=b""):
    # Reads until a single line (ending with \n) is available or the peer disconnects.
    try:
        while b"\n" not in buf:
            chunk = conn.recv(65535)
            if not chunk:
                return None, buf
            buf += chunk
        line, buf = buf.split(b"\n", 1)
        return line, buf
    except (ConnectionResetError, OSError):
        return None, buf

def handle(conn):
    try:
        chall = os.urandom(32)  # 2 blocks (no padding)
        if not safe_send(conn, BANNER + b"Challenge: " + binascii.hexlify(chall) + b"\n"):
            return
        tries = 12289
        secs  = 29
        buf = b""
        while tries > 0 and secs > 0:
            if not safe_send(conn, f"\n{secs} seconds remain. {tries} tries left.\n".encode()):
                return
            if not safe_send(conn, b"Please submit authorization token.\n"):
                return

            line, buf = recv_until_newline(conn, buf)
            if line is None:
                # client disconnected
                return

            # Process possibly multiple hex lines (client may have buffered sends)
            lines = [line]
            # If buffer already has more lines queued, drain them quickly (up to 512 to avoid abuse)
            drain = 0
            while b"\n" in buf and drain < 512:
                l, buf = buf.split(b"\n", 1)
                lines.append(l)
                drain += 1

            for l in lines:
                if not l:
                    continue
                tries -= 1
                try:
                    raw = binascii.unhexlify(l.strip())
                    iv, ct = raw[:16], raw[16:]
                    cipher = AES.new(KEY, AES.MODE_CBC, iv)
                    pt = cipher.decrypt(ct)
                    try:
                        m = unpad(pt, 16)
                        if m == chall:
                            safe_send(conn, b"Authorization verified. The flag is utflag{oracle_padded_oops}\n")
                            return
                        else:
                            if not safe_send(conn, b"Invalid challenge provided.\n"):
                                return
                    except ValueError:
                        if not safe_send(conn, b"Decryption failed.\n"):
                            return
                except Exception:
                    if not safe_send(conn, b"Decryption failed.\n"):
                        return
            secs -= 1
    finally:
        try:
            conn.close()
        except Exception:
            pass

def main():
    host, port = "0.0.0.0", 4356
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(64)
    print(f"Local oracle on {host}:{port}")
    while True:
        try:
            c, _ = s.accept()
        except Exception:
            continue
        threading.Thread(target=handle, args=(c,), daemon=True).start()

if __name__ == "__main__":
    main()
