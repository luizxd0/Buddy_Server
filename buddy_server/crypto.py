
from Crypto.Cipher import AES
import binascii
import hashlib

# CHAVES DE CRIPTOGRAFIA (AES-128 ECB)
# Baseadas no código Rust fornecido pelo usuário.
# OBS: O código Rust usa hex::decode, então as chaves devem ser convertidas de Hex para Bytes.

# CHAVES DE CRIPTOGRAFIA (AES-128 ECB)
# Baseadas no código Java (GunBound-Java-main)
# A chave estática "FFB3B3...EB0" é chamada de FIXED_KEY e usada para decriptar pacotes estáticos.
# O código Java não diferencia Launcher/Broker explicitamente com chaves diferentes no staticCipher, 
# mas usa a mesma FIXED_KEY. Vamos atualizar para usar essa chave confirmada.

# Java GunBoundCipher: FIXED_KEY for static decrypt (game login 0x1010 username block).
# RE: Client table at 0x0057a448 (first 16 bytes) = this same key; used in FUN_004fa880 via FUN_004c1580.
# FUN_004fa880: SHA-1(username || auth_token) -> 20-byte digest; then AES-ECB(key, digest[0:16]) || AES-ECB(key, digest[16:20]+pad) -> 32-byte payload.
KEY_GAME_STATIC_HEX = "FFB3B3BEAE97AD83B9610E23A43C2EB0"
# Buddy Server explicit hardcoded key from Gunbound.gme at VA 0x5516b4
KEY_BUDDY_STATIC_HEX = "2C45926CF3396642B670D006A1FA8182"

# Broker/other traffic
KEY_STATIC_HEX = "A92753041BFCACE65B2338346846038C"

# Mantendo as antigas como backup comentado caso a versão do client varie
# KEY_LAUNCHER_HEX = "FAAA85AA40AAAAAAAAAAAA7AAAAAAAAA"
# KEY_BROKER_HEX = "AAAAA5AA41BFCAAAAAAAAAA3AA84AA3A"

class GBCrypto:
    @staticmethod
    def decrypt_game_static(data_16_bytes: bytes) -> bytes:
        """Decrypt first 16 bytes of 0x1010 login payload (username). Java: gunboundStaticDecrypt, FIXED_KEY."""
        if len(data_16_bytes) < 16:
            return data_16_bytes
        key = binascii.unhexlify(KEY_GAME_STATIC_HEX)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(data_16_bytes[:16])

    @staticmethod
    def decrypt_buddy_static(data_16_bytes: bytes) -> bytes:
        """Decrypt first 16 bytes of buddy 0x1010 login payload. Extracted from Gunbound.gme VA 0x5516b4."""
        if len(data_16_bytes) < 16:
            return data_16_bytes
        key = binascii.unhexlify(KEY_BUDDY_STATIC_HEX)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(data_16_bytes[:16])

    @staticmethod
    def decrypt_broker_block(data_16_bytes: bytes) -> bytes:
        """Decrypt first 16 bytes with broker key (some buddy clients use this for 0x1010)."""
        if len(data_16_bytes) < 16:
            return data_16_bytes
        key = binascii.unhexlify(KEY_STATIC_HEX)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(data_16_bytes[:16])

    @staticmethod
    def decrypt_with_key_bytes(data_16_bytes: bytes, key: bytes) -> bytes:
        """Decrypt first 16 bytes with an arbitrary 16-byte key (for RE: token-derived keys)."""
        if len(data_16_bytes) < 16 or len(key) < 16:
            return b""
        key = (key + b"\x00" * 16)[:16]
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(data_16_bytes[:16])

    @staticmethod
    def decrypt_blocks_ecb(data: bytes, key_hex: str) -> bytes:
        """Decrypt data in 16-byte ECB blocks (no padding). Used for full payload try."""
        if len(data) % 16 != 0:
            data = data + b'\x00' * ((16 - len(data) % 16) % 16)
        key = binascii.unhexlify(key_hex)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(data)

    # ----- FUN_004fa880: SHA-1 + AES 0x1010 login payload -----

    @staticmethod
    def decrypt_1010_sha1_payload(payload_32: bytes, key_hex: str = KEY_GAME_STATIC_HEX) -> bytes | None:
        """
        Decrypt 32-byte 0x1010 payload (FUN_004fa880): two AES-ECB blocks with game key.
        Returns first 20 bytes as the SHA-1 digest, or None if payload length < 32.
        """
        if len(payload_32) < 32:
            return None
        key = binascii.unhexlify(key_hex)
        cipher = AES.new(key, AES.MODE_ECB)
        block1 = cipher.decrypt(payload_32[0:16])
        block2 = cipher.decrypt(payload_32[16:32])
        return (block1 + block2)[:20]

    @staticmethod
    def compute_client_sha1_username_token(username: str | bytes, auth_token_4: bytes) -> bytes:
        """
        Replicate client SHA-1 input: username (null-term string) then auth_token (4 bytes).
        FUN_004fa880: SHA-1 update with string at EAX, then update with param_3.
        """
        if isinstance(username, str):
            username = username.encode("utf-8")
        return hashlib.sha1(username + auth_token_4[:4]).digest()

    @staticmethod
    def decrypt(data: bytes, key_type: int) -> bytes:
        """
        Descriptografa um bloco de dados usando AES-128-ECB.
        :param data: Bytes criptografados.
        :param key_type: (Ignorado agora, usa FIXED_KEY única do Java)
        :return: Bytes descriptografados.
        """
        try:
            # Usando a chave única encontrada no emulador Java
            key = binascii.unhexlify(KEY_STATIC_HEX)
            
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted = cipher.decrypt(data)
            return decrypted
        except Exception as e:
            print(f"Decryption Error: {e}")
            return data 

    @staticmethod
    def encrypt(data: bytes, key_type: int) -> bytes:
        """
        Criptografa dados usando AES-128-ECB.
        """
        try:
            key = binascii.unhexlify(KEY_STATIC_HEX)
            
            cipher = AES.new(key, AES.MODE_ECB)
            
            pad_len = 16 - (len(data) % 16)
            if pad_len != 16:
                data += b'\0' * pad_len
                
            encrypted = cipher.encrypt(data)
            return encrypted
        except Exception as e:
            print(f"Encryption Error: {e}")
            return data
