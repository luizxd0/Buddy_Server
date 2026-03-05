
import os

class Config:
    # Server Settings
    HOST = '0.0.0.0'
    PORT = 8352 # 8352 default, but Reg says 8355 (0x20A3)
    
    # Database Settings
    DB_HOST = '127.0.0.1'
    DB_USER = 'gbth'
    DB_PASS = "gbthclassic200591"
    DB_NAME = "gbth"
    DB_PORT = 3306
    
    # Combined Dictionary for easier access
    DB_CONFIG = {
        'user': DB_USER,
        'password': DB_PASS,
        'host': DB_HOST,
        'database': DB_NAME,
        'port': DB_PORT
    }

    # Packet Settings
    HEADER_SIZE = 4 # Adjust based on actual protocol (usually 2 bytes len + 2 bytes ID or similar)

    # Login: user is resolved from 0x1000/0x1010 payload (length-prefixed string, null-terminated, or
    # decrypted first 16 bytes with game/broker key). No fallback to a fixed user; user must exist in game table.

    # EXPERIMENTAL FEATURES
    BUDDY_LIST_NULL_TERMINATED = True      # Use write_string_null instead of write_string
    BUDDY_LIST_COUNT_AS_INT = True         # Use write_int(count) instead of write_byte(count)
    BUDDY_LIST_ONE_PER_PACKET = False      # Send one 0x1010 packet per buddy
    BUDDY_LIST_DEBUG_HEX = True            # Print hex dump of outgoing buddy list (client may only parse single-buddy packets)
    # True = send buddy list (0x1010) before login OK (0x1001); some clients only render list if it arrives first
    BUDDY_LIST_BEFORE_LOGIN_RESP = False
