import sys, zlib
import zlib as _zlib

def adler32(data: bytes) -> int:
    return _zlib.adler32(data) & 0xFFFFFFFF

def jmd_key(original_key: int) -> bytes:
    out = bytearray(64)
    cur = (original_key ^ 0x8473FBC1) & 0xFFFFFFFF
    for i in range(16):
        out[i*4:(i+1)*4] = cur.to_bytes(4, 'little')
        cur = (cur - 0x7B8C043F) & 0xFFFFFFFF
    return bytes(out)

def jmd_decrypt(key_int: int, data: bytes) -> bytes:
    key = jmd_key(key_int)
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ key[i & 63]
    return bytes(out)

def Data0m_byte(raw: bytes):
    if len(raw) < 10:
        raise ValueError
    total_len = int.from_bytes(raw[0:4], 'little')
    if raw[4] != 0x53:
        raise ValueError
    mode = raw[5]
    encrypted = (mode & 2) != 0
    compressed = (mode & 1) != 0
    hashv = int.from_bytes(raw[6:10], 'little')
    idx = 10
    key = 0
    if encrypted:
        key = int.from_bytes(raw[idx:idx+4], 'little')
        idx += 4
    dec_size = None
    if compressed:
        dec_size = int.from_bytes(raw[idx:idx+4], 'little', signed=True)
        idx += 4
    payload = raw[idx:]
    return encrypted, compressed, hashv, key, dec_size, payload

def main():
    if len(sys.argv) < 2:
        return
    path = sys.argv[1]
    try:
        raw = open(path, "rb").read()
    except Exception:
        return

    try:
        encrypted, compressed, hashv, key, dec_size, payload = Data0m_byte(raw)
    except Exception:
        return

    if encrypted:
        try:
            payload = jmd_decrypt(key, payload)
        except Exception:
            return

    if compressed:
        try:
            payload = zlib.decompress(payload)
        except Exception:
            pass

    chk = adler32(payload)
    out_name = "DataSub.bin"
    try:
        with open(out_name, "wb") as f:
            f.write(payload)
    except Exception:
        return

if __name__ == "__main__":
    main()
