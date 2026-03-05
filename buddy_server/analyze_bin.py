
import string

def extract_strings_from_data(data: bytes, min_length=10):
    result = []
    current_string = ""
    printable = set(bytes(string.printable, 'ascii'))
    for byte in data:
        if byte in printable and byte not in [0x09, 0x0A, 0x0D]:
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                result.append(current_string)
            current_string = ""
    if len(current_string) >= min_length:
        result.append(current_string)
    return result


def extract_strings(filename, min_length=10):
    with open(filename, 'rb') as f:
        data = f.read()
    return extract_strings_from_data(data, min_length)

def filter_strings(strings):
    keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "JOIN", 
                "Error", "Fail", "Connect", "Socket", "Port", "IP", "Buddies", "Friend", "User",
                "Udp", "Center", "Register", "CTR_", "Listen", "REG_LOGIN", "REC_CENTER", "CENTER_",
                "Command", "CONFIG", "INIT", "Warning", "System", "Thread", "Queue", "Packet", "Msg"]
    filtered = []
    for s in strings:
        # Check if it looks like code or SQL or meaningful text
            filtered.append(s)
            
    return filtered

def extract_hex_keys(data: bytes, key_len_hex=32):
    """Find sequences of hex chars that could be AES-128 keys (32 hex = 16 bytes)."""
    import re
    # 32+ hex chars (optionally with spaces)
    pattern = re.compile(rb'[0-9A-Fa-f]{' + str(key_len_hex).encode() + rb'}[0-9A-Fa-f]*')
    keys = []
    for m in pattern.finditer(data):
        s = m.group().decode("ascii", errors="ignore")
        if len(s) >= key_len_hex:
            keys.append(s[:key_len_hex])
    return list(dict.fromkeys(keys))  # unique, order preserved


if __name__ == "__main__":
    import os
    # Default: look for BuddyServ in common places; override with BUDDY_BIN env
    default_bin = os.path.join(os.path.dirname(__file__), "3 - SERVIDOR", "BuddyServ", "BuddyServ2.exe")
    binaries = os.environ.get("BUDDY_BIN", default_bin).split(os.pathsep)
    if not os.path.isfile(binaries[0]):
        binaries = [
            "c:/Users/Eletrocel/.gemini/antigravity/playground/tachyon-glenn/3 - SERVIDOR/BuddyServ/BuddyServ2.exe"
        ]
    
    all_strings = []
    
    print("Starting DEEP DUMP analysis on all binaries...")
    
    for bin_path in binaries:
        if not os.path.isfile(bin_path):
            print(f"Skipping (not found): {bin_path}")
            continue
        print(f"Analyzing {bin_path}...")
        try:
            with open(bin_path, "rb") as f:
                data = f.read()
            strs = extract_strings_from_data(data, min_length=4)
            all_strings.extend([f"[{os.path.basename(bin_path)}] {s}" for s in strs])
            # Extract possible 32-char hex keys (AES-128)
            hex_keys = extract_hex_keys(data)
            if hex_keys:
                print(f"  Possible hex keys (32 chars): {len(hex_keys)}")
                for k in hex_keys[:20]:
                    print(f"    {k}")
        except Exception as e:
            print(f"Skipping {bin_path}: {e}")

    interesting_keywords = [
        "SVC_", "CTR_", "DBIN_", "REG_", "CENTER_", "BROKER_", 
        "SELECT", "INSERT", "UPDATE", "DELETE", "Expected", "Failed", 
        "Packet", "Socket", "Context", "User", "Game", "Buddy",
        "Invite", "INVITE", "Request", "REQUEST", "Add", "Friend", "Msg", "Chat",
        "AES", "Crypt", "encrypt", "decrypt", "0x1010", "1010", "key", "Key",
    ]
    
    filtered_soul = []
    
    for s in all_strings:
        if any(k in s for k in interesting_keywords) or "%" in s:
            filtered_soul.append(s)
            
    with open("full_soul_dump.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(filtered_soul))
        
    print(f"Dumped {len(filtered_soul)} interesting strings to full_soul_dump.txt")
