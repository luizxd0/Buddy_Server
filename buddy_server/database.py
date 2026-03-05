import mysql.connector
from mysql.connector import Error
from .config import Config

class Database:
    def __init__(self, db_config):
        self.db_config = db_config
        self.connection = None

    def connect(self):
        try:
            if self.connection:
                try:
                    self.connection.close()
                except Exception:
                    pass
            self.connection = mysql.connector.connect(**self.db_config)
            if self.connection.is_connected():
                self.connection.autocommit = True
                print("Database connected successfully")
                return True
        except Error as e:
            print(f"Error connecting to MySQL: {e}")
            return False

    def _ensure_connection(self):
        """Ensures the MySQL connection is alive, reconnecting if needed."""
        try:
            if not self.connection or not self.connection.is_connected():
                return self.connect()
            else:
                self.connection.ping(reconnect=True, attempts=3, delay=1)
                return True
        except Error:
            print("Refreshing lost MySQL connection...")
            try:
                if self.connection:
                    self.connection.close()
            except Exception:
                pass
            self.connection = None
            return self.connect()

    def _is_retryable_db_error(self, err):
        errno = getattr(err, "errno", None)
        return errno in (2006, 2013, 2055)

    def _query_with_retry(self, query, params=(), dictionary=False, fetch=None, commit=False):
        """
        Execute query with one reconnect retry on transient MySQL disconnects.
        fetch: None | 'one' | 'all'
        Returns rowcount when fetch is None, or fetched row(s) otherwise.
        """
        last_error = None
        for attempt in range(2):
            cursor = None
            try:
                if not self._ensure_connection() or not self.connection:
                    raise Error("MySQL connection unavailable")
                cursor = self.connection.cursor(dictionary=dictionary)
                cursor.execute(query, params)
                if commit:
                    self.connection.commit()
                if fetch == 'one':
                    return cursor.fetchone()
                if fetch == 'all':
                    return cursor.fetchall()
                return cursor.rowcount
            except Error as e:
                last_error = e
                if attempt == 0 and self._is_retryable_db_error(e):
                    print(f"MySQL transient error ({getattr(e, 'errno', '?')}), reconnecting and retrying query...")
                    try:
                        if self.connection:
                            self.connection.close()
                    except Exception:
                        pass
                    self.connection = None
                    continue
                raise
            finally:
                if cursor:
                    try:
                        cursor.close()
                    except Exception:
                        pass
        if last_error:
            raise last_error

    def disconnect(self):
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("MySQL connection is closed")

    def get_user_game_data(self, user_id_or_nickname):
        """
        Fetches user info and game data. Join to get numeric Id (UserNo).
        """
        query = """
            SELECT u.Id AS UserNo, g.UserId, g.NickName, g.TotalGrade, g.TotalRank, g.Guild
            FROM game g
            INNER JOIN user u ON u.UserId = g.UserId
            WHERE g.UserId = %s OR g.NickName = %s
        """
        try:
            return self._query_with_retry(
                query,
                (user_id_or_nickname, user_id_or_nickname),
                dictionary=True,
                fetch='one'
            )
        except Error:
            return None

    def get_user_game_data_by_id(self, user_no):
        """Fetches game data by numeric user Id."""
        query = """
            SELECT u.UserId, g.NickName, g.Gold, g.Cash, g.TotalGrade
            FROM user u
            LEFT JOIN game g ON u.UserId = g.UserId
            WHERE u.Id = %s
        """
        try:
            return self._query_with_retry(query, (user_no,), dictionary=True, fetch='one')
        except Error:
            return None

    def get_users_with_passwords(self):
        """Return list of (UserId, Password) for users that have a game row (for dynamic-key login try)."""
        try:
            rows = self._query_with_retry(
                "SELECT u.UserId, u.Password FROM user u INNER JOIN game g ON g.UserId = u.UserId",
                dictionary=True,
                fetch='all'
            )
            return [(r["UserId"], r["Password"]) for r in rows or []]
        except Error:
            return []

    def get_all_game_user_identifiers(self):
        """Return list of (UserId, NickName) for all game rows (for 0x1010 SHA1 digest match)."""
        try:
            rows = self._query_with_retry("SELECT UserId, NickName FROM game", dictionary=True, fetch='all')
            return [(r["UserId"], (r.get("NickName") or r.get("Nickname") or r["UserId"])) for r in rows or []]
        except Error:
            return []

    def get_user_by_nickname(self, nickname):
        """Resolve nickname to user id. sql_th: game.NickName -> user.Id, user.UserId."""
        try:
            # Join game and user to get both internal numeric ID and string UserId
            query = """
                SELECT u.Id as UserNo, u.UserId, g.NickName 
                FROM game g
                INNER JOIN user u ON u.UserId = g.UserId
                WHERE g.NickName = %s
            """
            result = self._query_with_retry(query, (nickname,), dictionary=True, fetch='one')
            if result:
                # Return standardized dict that include both IDs
                return {
                    'Id': result['UserId'],     # String login ID
                    'UserNo': result['UserNo'], # Numeric internal ID
                    'UserId': result['UserId'], # String login ID (duplicate key for safety)
                    'NickName': result['NickName']
                }
        except Error as e:
            print(f"Error fetching user by nickname: {e}")
        return None

    def resolve_user_id(self, login_name):
        """
        Tries to resolve the string login name (e.g. 'teste') to the correct User ID for foreign keys.
        If the DB expects Integers for 'Id' in other tables, we must find the numeric ID here.
        """
        try:
            # First try matching by literal UserId
            res = self._query_with_retry(
                "SELECT Id FROM user WHERE UserId = %s",
                (login_name,),
                dictionary=True,
                fetch='one'
            )
            if res:
                return res['Id']

            # Then try matching by game NickName
            try:
                res = self._query_with_retry(
                    "SELECT u.Id FROM user u INNER JOIN game g ON g.UserId = u.UserId WHERE g.NickName = %s",
                    (login_name,),
                    dictionary=True,
                    fetch='one'
                )
                if res:
                    return res['Id']
            except Error:
                # Login column might not exist or be named differently (e.g. Username)
                pass

            return login_name 
            
        except Error as e:
            print(f"Error resolving user ID: {e}")
            return login_name

    def get_current_user_location(self, user_id):
        """
        Checks if a user is online and where.
        Query from binary: SELECT Context, ServerIP, ServerPort FROM CurrentUser WHERE Id='%s'
        """
        try:
            return self._query_with_retry(
                "SELECT Context, ServerIP, ServerPort FROM CurrentUser WHERE Id = %s",
                (user_id,),
                dictionary=True,
                fetch='one'
            )
        except Error:
            return None

    def check_game_context(self, user_id):
        """
        Verifica se o usuário está em contexto de jogo (Context != 0/Lobby).
        Baseado na análise do GunboundServ.exe que faz REPLACE CurrentUser ... Context=...
        Retorna True se estiver em jogo.
        """
        loc = self.get_current_user_location(user_id)
        if loc and loc.get('Context', 0) > 1: # Assumindo 0=Lobby, 1=RoomWait, 2=Game? 
             # Na dúvida, se tem contexto e ServerPort > 0, está conectado num GameServer.
             return True
        return False

    def login_log(self, user_id, ip, port, server_ip, server_port, country):
        """
        Logs a user login.
        Query: INSERT INTO LoginLog (Id, Ip, Ip_v, Port, Port_v, Time, ServerIp, ServerPort, Country) VALUES ...
        """
        query = """
            INSERT INTO LoginLog (Id, Ip, Ip_v, Port, Port_v, Time, ServerIp, ServerPort, Country) 
            VALUES (%s, %s, 0, %s, 0, NOW(), %s, %s, %s)
        """
        try:
            # Ip_v and Port_v might be virtual IPs/Ports, setting to 0 for now
            self._query_with_retry(query, (user_id, ip, port, server_ip, server_port, country), commit=True)
        except Error as e:
            print(f"Error writing login log: {e}")

    
    # -------------------------------------------------------------------------
    # ANALYZED QUERIES (BuddyServ2.exe)
    # -------------------------------------------------------------------------
    
    # -------------------------------------------------------------------------
    # ID MAPPING (Login String <-> UserNo Int)
    # -------------------------------------------------------------------------
    def get_userno(self, login_id):
        """Converts Login ID (UserId string) to numeric Id. Supports sql_th: user.Id, user.UserId."""
        try:
            res = self._query_with_retry(
                "SELECT Id FROM user WHERE UserId = %s",
                (login_id,),
                fetch='one'
            )
            if res:
                return res[0]
        except Error:
            pass
        try:
            res = self._query_with_retry(
                "SELECT u.Id FROM user u INNER JOIN game g ON g.UserId = u.UserId WHERE g.NickName = %s",
                (login_id,),
                fetch='one'
            )
            if res:
                return res[0]
        except Error:
            pass
        return None

    def get_login_id(self, userno):
        """Converts numeric Id to Login ID (UserId string)."""
        try:
            res = self._query_with_retry("SELECT UserId FROM user WHERE Id = %s", (userno,), fetch='one')
            if res:
                return res[0]
        except Error:
            pass
        return str(userno)

    # -------------------------------------------------------------------------
    # BUDDY LIST OPERATIONS (With Conversion)
    # -------------------------------------------------------------------------
    
    def add_buddy(self, user_id, friend_id):
        # user_id and friend_id are STRINGS (Logins).
        # We must convert to INTs for DB.
        
        u_no = self.get_userno(user_id)
        f_no = self.get_userno(friend_id)
        
        if not u_no or not f_no:
            print(f"Cannot add buddy: UserNo not found for {user_id} or {friend_id}")
            return False

        try:
            # Check if exists (Using Ints)
            check_query = "SELECT * FROM BuddyList WHERE Id = %s AND Buddy = %s"
            exists = self._query_with_retry(check_query, (u_no, f_no), fetch='one')
            if exists:
                return False

            query = "INSERT INTO BuddyList (Id, Buddy, Category) VALUES (%s, %s, %s)"
            self._query_with_retry(query, (u_no, f_no, 'General'), commit=True)
            return True
        except Error as e:
            print(f"Error adding buddy: {e}")
            return False

    def remove_buddy(self, user_id, friend_id):
        u_no = self.get_userno(user_id)
        f_no = self.get_userno(friend_id)
        
        if not u_no or not f_no:
            return False

        try:
            query = "DELETE FROM BuddyList WHERE Id = %s AND Buddy = %s"
            affected = self._query_with_retry(query, (u_no, f_no), commit=True)
            return affected > 0
        except Error as e:
            print(f"Error removing buddy: {e}")
            return False
            
    
    def get_buddy_list(self, user_id):
        """
        Legacy wrapper for backward compatibility.
        Returns list of dicts: [{'friend_id': 'login'}, ...]
        """
        self._ensure_connection()
        full_list = self.get_full_buddy_list(user_id)
        # Convert to old format
        simple_list = []
        for f in full_list:
            # map 'Id' or 'Nickname' to 'friend_id' depending on what legacy code expected
            # Legacy code expected 'friend_id' (login)
            simple_list.append({'friend_id': f['Id'], 'Category': f['Category']})
        return simple_list

    def get_full_buddy_list(self, user_id):
        """
        Retrieves the complete buddy list. sql_th: BuddyList.Id/Buddy = user.Id; friend Id/Nickname from user + game.
        """
        self._ensure_connection()
        u_no = self.get_userno(user_id)
        if not u_no:
            return []
        try:
            # sql_th: user.Id, user.UserId; game.NickName (column name in schema); BuddyList.Id=owner, Buddy=friend
            query = """
                SELECT u.UserId AS Id, u.Id AS UserNo, COALESCE(g.NickName, u.UserId) AS NickName, 
                       g.TotalGrade, g.TotalRank, g.Guild, b.Category
                FROM BuddyList b
                INNER JOIN user u ON u.Id = b.Buddy
                LEFT JOIN game g ON g.UserId = u.UserId
                WHERE b.Id = %s
            """
            results = self._query_with_retry(query, (u_no,), dictionary=True, fetch='all')
            return results if results is not None else []
        except Error as e:
            print(f"Error fetching full buddy list: {e}")
            return []

    def get_users_info(self, user_ids):
        """Return list of {Id, NickName} for given UserIds (login names). sql_th: game.NickName."""
        if not user_ids:
            return []
        format_strings = ','.join(['%s'] * len(user_ids))
        try:
            query = f"""
                SELECT u.UserId AS Id, COALESCE(g.NickName, u.UserId) AS NickName
                FROM user u LEFT JOIN game g ON g.UserId = u.UserId
                WHERE u.UserId IN ({format_strings})
            """
            return self._query_with_retry(query, tuple(user_ids), dictionary=True, fetch='all') or []
        except Error as e:
            print(f"Error checking users info: {e}")
            return []

    # -------------------------------------------------------------------------
    # OFFLINE PACKET HANDLING (Analyzed from BuddyServ2)
    # -------------------------------------------------------------------------
    
    def save_packet(self, sender_id, receiver_id, code, body):
        self._ensure_connection()
        print(f"[DEBUG] save_packet called: sender={sender_id}, receiver={receiver_id}, code={hex(code)}")
        
        # Packet/OfflineMsg likely uses Ints too based on logs.
        s_no = self.get_userno(sender_id)
        r_no = self.get_userno(receiver_id)
        
        print(f"[DEBUG] Resolved UserNos: send={s_no}, recv={r_no}")
        
        if not s_no or not r_no:
            print(f"[ERROR] Cannot save packet: UserNo not found (s={s_no}, r={r_no})")
            return False
            
        try:
            # Avoid queue amplification: do not store exact duplicate pending packets.
            dedupe_query = """
                SELECT SerialNo
                FROM Packet
                WHERE Receiver = %s AND Sender = %s AND Code = %s AND Body = %s
                ORDER BY SerialNo DESC
                LIMIT 1
            """
            exists = self._query_with_retry(dedupe_query, (r_no, s_no, code, body), fetch='one')
            if exists:
                print(f"[DEBUG] Duplicate offline packet skipped: send={s_no}, recv={r_no}, code={code}")
                return True

            query = """
                INSERT INTO Packet (Receiver, Sender, Code, Body, Time) 
                VALUES (%s, %s, %s, %s, NOW())
            """
            print(f"[DEBUG] Executing INSERT: recv={r_no}, send={s_no}, code={code}, body_len={len(body)}")
            self._query_with_retry(query, (r_no, s_no, code, body), commit=True)
            print(f"[SUCCESS] Comitted to database!")
            print(f"Saved offline packet from {sender_id}({s_no}) to {receiver_id}({r_no})")
            return True
        except Error as e:
            print(f"[ERROR] Error saving offline packet: {e}")
            return False

    def get_packets(self, receiver_id):
        self._ensure_connection()
        r_no = self.get_userno(receiver_id)
        print(f"DEBUG: Checking offline packets for {receiver_id} (UserNo: {r_no})")
        if not r_no:
            return []
        try:
            packets_raw = self._query_with_retry(
                "SELECT SerialNo, Sender, Code, Body FROM Packet WHERE Receiver = %s ORDER BY SerialNo ASC",
                (r_no,),
                dictionary=True,
                fetch='all'
            ) or []
        except Error as e:
            print(f"Error fetching packets: {e}")
            return []
        print(f"DEBUG: Found {len(packets_raw)} packets.")
        
        # Convert Sender (Int) back to String
        final_packets = []
        for p in packets_raw:
            sender_no = p['Sender']
            # Sometimes sender might be textual if legacy? Assuming Int based on error.
            # If sender column is Int, get_login_id.
            p['Sender'] = self.get_login_id(sender_no)
            final_packets.append(p)
        return final_packets

    def delete_packet(self, serial_no):
        """
        Deletes a specific packet after delivery.
        """
        try:
            self._query_with_retry("DELETE FROM Packet WHERE SerialNo = %s", (serial_no,), commit=True)
        except Error as e:
            print(f"Error deleting packet {serial_no}: {e}")

    
    # -------------------------------------------------------------------------
    # GROUP MANAGEMENT
    # -------------------------------------------------------------------------
    def move_buddy_to_group(self, user_id, friend_id, new_category):
        """
        Moves a friend to a different category/group.
        Query: UPDATE BuddyList SET Category='%s' WHERE Id='%s' AND Buddy='%s'
        """
        try:
            query = "UPDATE BuddyList SET Category = %s WHERE Id = %s AND Buddy = %s"
            self._query_with_retry(query, (new_category, user_id, friend_id), commit=True)
            return True
        except Error as e:
            print(f"Error moving buddy: {e}")
            return False

    def rename_group(self, user_id, old_category, new_category):
        """
        Renames an entire group of friends.
        Query: UPDATE BuddyList SET Category='%s' WHERE Id='%s' AND Category='%s'
        """
        try:
            query = "UPDATE BuddyList SET Category = %s WHERE Id = %s AND Category = %s"
            self._query_with_retry(query, (new_category, user_id, old_category), commit=True)
            return True
        except Error as e:
            print(f"Error renaming group: {e}")
            return False
            
    # -------------------------------------------------------------------------
    # SEARCH & UTILS (Enhanced with Phone Support)
    # -------------------------------------------------------------------------
    def get_user_by_search_term(self, term):
        """
        Searches for a user by Nickname OR Phone Number.
        """
        # Try finding by Nickname first joining with game
        query = """
            SELECT u.UserId as Id, g.NickName 
            FROM user u
            INNER JOIN game g ON u.UserId = g.UserId
            WHERE g.NickName = %s OR u.UserId = %s
        """
        try:
            res = self._query_with_retry(query, (term, term), dictionary=True, fetch='one')
        except Error as e:
            print(f"Error searching user: {e}")
            return None
        
        if not res:
            # If not found, try Phone Number
            # Note: The column 'Phone_number' is derived from the binary string.
            # Make sure this column exists in your User table schema!
            try:
                # We use parameterized query, but logic is "Phone_number = %s"
                query_phone = "SELECT Id, Nickname FROM User WHERE Phone_number = %s"
                res = self._query_with_retry(query_phone, (term,), dictionary=True, fetch='one')
            except Error:
                # Column might not exist in some DB versions, harmless fallback.
                pass
        return res

    def check_user_exists(self, nickname):
        # Kept for backward compat, but redirects to enhanced search
        return self.get_user_by_search_term(nickname)
