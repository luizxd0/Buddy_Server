import asyncio
import logging
import time
import struct
import binascii
from enum import IntEnum
from typing import Dict, Set, Optional

from .packets import PacketBuilder
from .constants import *

logger = logging.getLogger(__name__)

class UserStatus(IntEnum):
    """Estados possíveis de um usuário"""
    OFFLINE = 0
    ONLINE = 1          # Online no lobby
    BUSY = 2            # Ocupado (não pode receber convites)
    IN_GAME = 3         # Jogando
    AWAY = 4            # Ausente (idle)
    SPECTATING = 5      # Assistindo jogo
    IN_SHOP = 6         # Na loja
    HIDDEN = 255        # Invisível / Offline (usado por alguns clientes)
    
class UserStatusManager:
    """
    Gerenciador de status de usuários.
    
    Funcionalidades:
    - Rastreamento de status em tempo real
    - Notificação automática para amigos
    - Detecção de idle (auto-away)
    - Sincronização com GameServ
    - Persistência no banco de dados
    """
    
    # Packet IDs
    PKT_STATUS_UPDATE = 0xA510      # Cliente envia update
    PKT_STATUS_BROADCAST = 0x3011   # Servidor broadcast para amigos (was 0x3010, caused collision)
    PKT_STATUS_QUERY = 0xA511       # Cliente pergunta status
    PKT_STATUS_RESPONSE = 0xA512    # Resposta de query
    
    def __init__(self, server):
        self.server = server
        
        # Status atual de cada usuário
        self.user_status: Dict[str, UserStatus] = {}
        
        # Informações adicionais de status
        self.user_status_data: Dict[str, dict] = {}
        
        # Timestamp da última atividade
        self.last_activity: Dict[str, float] = {}
        
        # Configurações
        self.idle_timeout = 300  # 5 minutos para auto-away
        self.status_cache_time = 60  # Cache de 60s
        
        # Tasks
        self.idle_check_task = None
        
        # Stats
        self.stats = {
            'status_changes': 0,
            'broadcasts_sent': 0,
            'auto_away_triggered': 0
        }
    
    async def start(self):
        """Inicia o manager"""
        self.idle_check_task = asyncio.create_task(self._idle_check_loop())
        logger.info("UserStatusManager started")
    
    async def stop(self):
        """Para o manager"""
        if self.idle_check_task:
            self.idle_check_task.cancel()
            try:
                await self.idle_check_task
            except asyncio.CancelledError:
                pass
        logger.info("UserStatusManager stopped")
    
    def get_status(self, user_id: str) -> UserStatus:
        """Retorna status atual de um usuário"""
        return self.user_status.get(user_id, UserStatus.OFFLINE)
    
    def get_status_data(self, user_id: str) -> dict:
        """Retorna dados adicionais do status"""
        return self.user_status_data.get(user_id, {})
        
    def get_gunbound_status_bitmask(self, user_id: str) -> int:
        """
        Converte UserStatus e metadados para o bitmask de 2 bytes (short) do GunBound.
        
        Bitmask (visto em referências de emulação):
        - Bit 0: Online?
        - Bit 1: Busy?
        - Bit 4: In Game?
        - Outros bits podem representar ChannelID (bits 8-15?)
        
        Mapeamento comum:
        - 18 (0x0012) = Online (Bit 1 + Bit 4?)
        - 0 = Offline
        """
        status = self.get_status(user_id)
        data = self.get_status_data(user_id)
        
        if status == UserStatus.OFFLINE:
            return 0
            
        # Base online status (usually 0x0012 or similar)
        # Vamos usar 0x0012 como base e ajustar
        bitmask = 0x0012
        
        if status == UserStatus.IN_GAME:
            bitmask |= 0x0004 # Exemplo bit de jogo
            
        # Adiciona Channel/World info se disponível nos dados
        # world_id = data.get('world_id', 0)
        # channel_id = data.get('channel_id', 0)
        # bitmask |= (channel_id << 8)
        
        return bitmask
    
    async def set_status(self, user_id: str, new_status: UserStatus, 
                        data: dict = None, broadcast: bool = True):
        """
        Define novo status para usuário.
        
        Args:
            user_id: ID do usuário
            new_status: Novo status
            data: Dados adicionais (ex: room_id, game_name)
            broadcast: Se deve notificar amigos
            
        Returns:
            bool: True se mudou com sucesso
        """
        old_status = self.user_status.get(user_id, UserStatus.OFFLINE)
        
        # Se não mudou, não faz nada
        if old_status == new_status and not data:
            return False
        
        # Atualiza status
        self.user_status[user_id] = new_status
        
        if data:
            if user_id not in self.user_status_data:
                self.user_status_data[user_id] = {}
            self.user_status_data[user_id].update(data)
        
        # Atualiza última atividade
        self.last_activity[user_id] = time.time()
        
        self.stats['status_changes'] += 1
        
        logger.info(f"[STATUS] {user_id}: {old_status.name} -> {new_status.name}")
        
        # Persiste no banco (CurrentUser table)
        await self._persist_status(user_id, new_status, data)
        
        # Notifica amigos
        if broadcast:
            await self._broadcast_status_change(user_id, new_status, data)
        
        return True
    
    async def user_login(self, user_id: str):
        """Registra login de usuário"""
        await self.set_status(user_id, UserStatus.ONLINE)
        logger.info(f"[STATUS] User {user_id} logged in -> ONLINE")
    
    async def user_logout(self, user_id: str):
        """Registra logout de usuário"""
        await self.set_status(user_id, UserStatus.OFFLINE)
        
        # Remove do cache
        self.user_status.pop(user_id, None)
        self.user_status_data.pop(user_id, None)
        self.last_activity.pop(user_id, None)
        
        logger.info(f"[STATUS] User {user_id} logged out -> OFFLINE")
    
    async def user_enter_game(self, user_id: str, game_data: dict):
        """
        Usuário entrou em uma partida.
        
        Args:
            user_id: ID do usuário
            game_data: Dados do jogo (room_id, room_name, server_ip, etc)
        """
        await self.set_status(user_id, UserStatus.IN_GAME, game_data)
        logger.info(f"[STATUS] {user_id} entered game: {game_data.get('room_name', 'Unknown')}")
    
    async def user_leave_game(self, user_id: str):
        """Usuário saiu da partida"""
        await self.set_status(user_id, UserStatus.ONLINE)
        # Limpa dados de jogo
        if user_id in self.user_status_data:
            self.user_status_data[user_id].pop('room_id', None)
            self.user_status_data[user_id].pop('room_name', None)
        
        logger.info(f"[STATUS] {user_id} left game -> ONLINE")
    
    async def user_activity(self, user_id: str):
        """Registra atividade do usuário (previne auto-away)"""
        self.last_activity[user_id] = time.time()
        
        # Se estava AWAY, volta para ONLINE
        if self.get_status(user_id) == UserStatus.AWAY:
            await self.set_status(user_id, UserStatus.ONLINE)
    
    async def query_status(self, client, target_id: str):
        """
        Cliente consulta status de outro usuário.
        
        Args:
            client: Cliente que pergunta
            target_id: ID do usuário consultado
        """
        status = self.get_status(target_id)
        data = self.get_status_data(target_id)
        
        # Envia resposta
        pkt = PacketBuilder(self.PKT_STATUS_RESPONSE)
        pkt.write_string(target_id)
        pkt.write_byte(status.value)
        
        # Dados adicionais baseado no status
        if status == UserStatus.IN_GAME:
            pkt.write_string(data.get('room_name', ''))
            pkt.write_int(data.get('room_id', 0))
        elif status == UserStatus.IN_SHOP:
            pkt.write_string(data.get('shop_section', 'Main'))
        
        await client.send_packet(pkt.build())
        logger.debug(f"Status query: {client.user_id} asked about {target_id} = {status.name}")
    
    async def _broadcast_status_change(self, user_id: str, new_status: UserStatus, data: dict):
        """
        Envia notificação de mudança de status para todos os amigos online.
        
        Args:
            user_id: Usuário que mudou
            new_status: Novo status
            data: Dados adicionais
        """
        # Busca lista de amigos
        buddies = self.server.db.get_buddy_list(user_id)
        if not buddies:
            return
        
        friend_ids = [b.get('FriendId') or b.get('friend_id') or b.get('Id') for b in buddies]
        friend_ids = [fid for fid in friend_ids if fid]
        
        # Para cada amigo online, envia notificação
        for friend_id in friend_ids:
            uid_lower = friend_id.lower()
            friend_session = self.server.user_sessions.get(uid_lower)
            
            if friend_session:
                try:
                    # 0x2021 (SVC_RELAY_BUDDY_REQ) - 60 bytes total
                    # Layout: Nick(16) + Nick(16) + UserNo(4) + Status(2) + Rank(2) + MetaPad(16)
                    buddy_data = self.server.db.get_user_game_data(user_id) or {}
                    nick_val = buddy_data.get('NickName') or user_id
                    
                    status = self.get_gunbound_status_bitmask(user_id)
                    rank = int(buddy_data.get('TotalGrade') or 0)
                    user_no = int(buddy_data.get('UserNo') or 0)
                    guild_name = buddy_data.get('Guild') or ""

                    uid_b = user_id.encode('latin-1', errors='ignore')[:15].ljust(16, b'\x00')
                    nick_b = nick_val.encode('latin-1', errors='ignore')[:15].ljust(16, b'\x00')
                    guild_b = guild_name.encode('latin-1', errors='ignore')[:7].ljust(8, b'\x00')

                    # Metadata 24 bytes (index 4=Status, index 18=UserNo, index 20=Rank)
                    meta = bytearray(24)
                    struct.pack_into('<H', meta, 4, status)
                    struct.pack_into('<H', meta, 18, user_no & 0xFFFF)
                    struct.pack_into('<H', meta, 20, rank)

                    relay_upd = PacketBuilder(SVC_RELAY_BUDDY_REQ)
                    relay_upd.write_bytes(uid_b)
                    relay_upd.write_bytes(nick_b)
                    relay_upd.write_bytes(bytes(meta))
                    
                    await friend_session.send_packet(relay_upd.build())
                    
                    logger.info(f"Broadcasted Status (0x2021): UID={user_id}, Status={hex(status)}, Guild='{guild_name}'")
                    self.stats['broadcasts_sent'] += 1
                    
                except Exception as e:
                    logger.error(f"Error broadcasting to {friend_id}: {e}")
        
        logger.debug(f"Broadcasted status change to {len(friend_ids)} friends")
    
    async def _persist_status(self, user_id: str, status: UserStatus, data: dict):
        """
        Persiste status no banco de dados (CurrentUser table).
        
        Estrutura (baseada em análise):
        UPDATE CurrentUser SET Context=%d, ServerIP=%s, ServerPort=%d WHERE Id=%s
        ServerIP/ServerPort = game server address (where user is playing), NOT client IP.
        Client IP is stored in LoginLog. Use 0.0.0.0 when not IN_GAME so it's clear they're in lobby.
        """
        try:
            cursor = self.server.db.connection.cursor()
            # ServerIP/Port = game server only when IN_GAME; otherwise 0.0.0.0:0
            if status == UserStatus.IN_GAME and data:
                server_ip = data.get('server_ip', '127.0.0.1')
                server_port = data.get('server_port', 8400)
            else:
                server_ip = '0.0.0.0'
                server_port = 0
            
            # Verifica se já existe
            check_query = "SELECT Id FROM CurrentUser WHERE Id = %s"
            cursor.execute(check_query, (user_id,))
            exists = cursor.fetchone()
            
            if exists:
                update_query = """
                    UPDATE CurrentUser 
                    SET Context = %s, ServerIP = %s, ServerPort = %s 
                    WHERE Id = %s
                """
                cursor.execute(update_query, (status.value, server_ip, server_port, user_id))
            else:
                insert_query = """
                    INSERT INTO CurrentUser (Id, Context, ServerIP, ServerPort) 
                    VALUES (%s, %s, %s, %s)
                """
                cursor.execute(insert_query, (user_id, status.value, server_ip, server_port))
            
            self.server.db.connection.commit()
            cursor.close()
            
        except Exception as e:
            logger.error(f"Error persisting status to DB: {e}")
    
    async def _idle_check_loop(self):
        """Loop que detecta usuários idle e muda para AWAY"""
        try:
            while True:
                await asyncio.sleep(60)  # Check a cada minuto
                
                now = time.time()
                
                for user_id, last_active in list(self.last_activity.items()):
                    # Só aplica a usuários ONLINE (não em jogo, etc)
                    current_status = self.get_status(user_id)
                    if current_status != UserStatus.ONLINE:
                        continue
                    
                    # Verifica timeout
                    idle_time = now - last_active
                    if idle_time > self.idle_timeout:
                        logger.info(f"[IDLE] {user_id} idle for {idle_time:.0f}s -> AWAY")
                        await self.set_status(user_id, UserStatus.AWAY)
                        self.stats['auto_away_triggered'] += 1
                
        except asyncio.CancelledError:
            logger.info("Idle check loop cancelled")
    
    def get_online_count(self) -> int:
        """Retorna quantidade de usuários online"""
        return len([s for s in self.user_status.values() if s != UserStatus.OFFLINE])
    
    def get_status_distribution(self) -> dict:
        """Retorna distribuição de status"""
        distribution = {}
        for status in UserStatus:
            count = len([s for s in self.user_status.values() if s == status])
            distribution[status.name] = count
        return distribution
    
    def get_users_by_status(self, status: UserStatus) -> list:
        """Retorna lista de usuários em um status específico"""
        return [uid for uid, s in self.user_status.items() if s == status]
    
    def get_stats(self):
        """Retorna estatísticas"""
        return {
            **self.stats,
            'online_users': self.get_online_count(),
            'status_distribution': self.get_status_distribution()
        }
    
    async def handle_status_update_packet(self, client, payload):
        """
        Handler para pacote de atualização de status enviado pelo cliente.
        
        Estrutura esperada:
        - NewStatus: Byte
        - Data: Variável (dependendo do status)
        """
        try:
            from .packets import PacketReader
            reader = PacketReader(payload)
            
            new_status_value = reader.read_byte()
            new_status = UserStatus(new_status_value)
            
            # Registra atividade
            await self.user_activity(client.user_id)
            
            # Parse dados adicionais baseado no status
            data = {}
            
            if new_status == UserStatus.BUSY:
                # Opcional: motivo
                if len(payload) > 1:
                    try:
                        data['reason'] = reader.read_string()
                    except:
                        pass
            
            # Atualiza status
            await self.set_status(client.user_id, new_status, data)
            
            # Confirma para cliente
            confirm = PacketBuilder(0xA513)  # STATUS_UPDATE_CONFIRM
            confirm.write_int(1)  # Success
            confirm.write_byte(new_status.value)
            await client.send_packet(confirm.build())
            
        except Exception as e:
            logger.error(f"Error handling status update packet: {e}")