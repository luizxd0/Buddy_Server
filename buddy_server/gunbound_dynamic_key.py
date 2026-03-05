"""
Java GunBoundCipher.getDynamicKey() port for buddy server.
Key = first 16 bytes of SHA-0(username + password + authToken), each DWORD byte-swapped to LE.
Used to decrypt 0x1010 payload bytes 0x20+ (and optionally try first 16 bytes if client uses dynamic for all).
"""

import struct


def _left_rotate(n: int, b: int) -> int:
    n = n & 0xFFFFFFFF
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


def _sha0_process_block(chunk: bytes) -> bytes:
    """Process 64-byte block; return 20-byte hash (SHA-0 variant)."""
    if len(chunk) != 64:
        raise ValueError("chunk must be 64 bytes")
    w = [0] * 80
    for i in range(16):
        w[i] = struct.unpack_from(">I", chunk, i * 4)[0]
    for i in range(16, 80):
        w[i] = _left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 0)
    a, b, c, d, e = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    for i in range(80):
        if 0 <= i <= 19:
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6
        temp = (_left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e, d, c, b, a = d, c, _left_rotate(b, 30), a, temp
    a = (a + 0x67452301) & 0xFFFFFFFF
    b = (b + 0xEFCDAB89) & 0xFFFFFFFF
    c = (c + 0x98BADCFE) & 0xFFFFFFFF
    d = (d + 0x10325476) & 0xFFFFFFFF
    e = (e + 0xC3D2E1F0) & 0xFFFFFFFF
    result = struct.pack(">IIIII", a, b, c, d, e)
    return result


def get_dynamic_key(username: str, password: str, auth_token: bytes) -> bytes:
    """
    Same as Java getDynamicKey(username, password, authToken).
    Returns 16 bytes for AES-128.
    """
    username_bytes = username.encode("utf-8")
    password_bytes = password.encode("utf-8")
    sha_state = username_bytes + password_bytes + auth_token
    message_bit_length = len(sha_state) * 8
    padded = bytearray(sha_state)
    padded.append(0x80)
    current_length = len(padded)
    num_zeros = 62 - current_length
    padded.extend(b"\x00" * num_zeros)
    padded.append((message_bit_length >> 8) & 0xFF)
    padded.append(message_bit_length & 0xFF)
    padded_block = bytes(padded)
    if len(padded_block) != 64:
        raise ValueError("padded block must be 64 bytes")
    sha0_hash = _sha0_process_block(padded_block)
    truncated = sha0_hash[:16]
    # DWORD swap to little-endian (each 4 bytes reversed)
    key = bytearray(16)
    for i in range(0, 16, 4):
        key[i : i + 4] = truncated[i : i + 4][::-1]
    return bytes(key)


def decrypt_first_block_with_dynamic_key(
    block_16: bytes, username: str, password: str, auth_token: bytes
) -> bytes:
    """Decrypt one 16-byte block with dynamic key (AES-128 ECB)."""
    from Crypto.Cipher import AES
    key = get_dynamic_key(username, password, auth_token)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block_16[:16])
