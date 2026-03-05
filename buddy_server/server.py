import asyncio
import logging
import socket
from .packets import Packet
from .handlers import handle_packet
from .database import Database
from .config import Config
from .constants import *
from .crypto import GBCrypto
from datetime import datetime

# ========== IMPORTAR NOVOS MANAGERS ==========
from .tunneling import TunnelingManager
from .invites import InviteManager
from .user_status import UserStatusManager
from .p2p_manager import P2PManager

logger = logging.getLogger(__name__)

# Packet Tracer
class PacketTracer:
    def __init__(self, filename="packet_trace.log"):
        self.filename = filename
    
    def log(self, direction, ip, port, data):
        try:
            with open(self.filename, "a") as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                hex_data = data.hex().upper()
                try:
                    ascii_data = "".join([chr(b) if 32 <= b <= 126 else '.' for b in data])
                except:
                    ascii_data = "???"
                
                f.write(f"[{timestamp}] [{direction}] {ip}:{port} | Len: {len(data)}\n")
                f.write(f"HEX: {hex_data}\n")
                f.write(f"ASC: {ascii_data}\n")
                f.write("-" * 50 + "\n")
        except Exception as e:
            logger.error(f"Trace Log Error: {e}")

tracer = PacketTracer()

class ClientConnection:
    def __init__(self, reader, writer, server):
        self.reader = reader
        self.writer = writer
        self.server = server
        self.ip = writer.get_extra_info('peername')
        self.user_id = None
        self.is_authenticated = False
        self.state = 0
        # 4-byte auth token sent in 0x1001 (Java game server sends this; client may use it for 0x1010 dynamic encrypt)
        self.auth_token = None

    async def send_packet(self, packet):
        try:
            data = packet.to_bytes()
            if self.ip:
                tracer.log("OUT", self.ip[0], self.ip[1], data)
                
            self.writer.write(data)
            await self.writer.drain()
            logger.info(f"[OUT] Sent Packet {hex(packet.packet_id)} to {self.ip} | Len: {len(data)}")
        except Exception as e:
            logger.error(f"Error sending packet to {self.ip}: {e}")

    async def run(self):
        try:
            wire_buffer = bytearray()

            while True:
                if len(wire_buffer) < 4:
                    block_data = await self.reader.read(4096)
                    if not block_data:
                        break

                    logger.info(f"RAW RECEIVED ({len(block_data)} bytes): {block_data.hex().upper()}")
                    if self.ip:
                        tracer.log("IN", self.ip[0], self.ip[1], block_data)
                    wire_buffer.extend(block_data)
                    continue

                raw_len = int.from_bytes(wire_buffer[0:2], "little")
                raw_id = int.from_bytes(wire_buffer[2:4], "little")
                is_plaintext = 4 <= raw_len <= 8192

                if is_plaintext:
                    packet_len = raw_len
                    if len(wire_buffer) < packet_len:
                        block_data = await self.reader.read(4096)
                        if not block_data:
                            break
                        logger.info(f"RAW RECEIVED ({len(block_data)} bytes): {block_data.hex().upper()}")
                        if self.ip:
                            tracer.log("IN", self.ip[0], self.ip[1], block_data)
                        wire_buffer.extend(block_data)
                        continue

                    packet_buf = bytes(wire_buffer[:packet_len])
                    del wire_buffer[:packet_len]

                    packet_id = raw_id
                    header = packet_buf[:4]
                    real_payload = packet_buf[4:]
                    logger.info(f"[IN] Recv Packet {hex(packet_id)} from {self.ip} | Len: {packet_len}")
                    await handle_packet(self, packet_id, header, real_payload)
                    continue

                # Encrypted path: need at least one full encrypted block (16 bytes).
                if len(wire_buffer) < 16:
                    block_data = await self.reader.read(4096)
                    if not block_data:
                        break
                    logger.info(f"RAW RECEIVED ({len(block_data)} bytes): {block_data.hex().upper()}")
                    if self.ip:
                        tracer.log("IN", self.ip[0], self.ip[1], block_data)
                    wire_buffer.extend(block_data)
                    continue

                decrypted_head = GBCrypto.decrypt(bytes(wire_buffer[:16]), 0)
                packet_len = int.from_bytes(decrypted_head[:2], "little")
                packet_id = int.from_bytes(decrypted_head[2:4], "little")

                if packet_len > 4096 or packet_len < 4:
                    logger.warning(
                        f"Invalid Packet Length after decryption: {packet_len}. Key might be wrong."
                    )
                    # Attempt stream resync on malformed encrypted frame.
                    del wire_buffer[:1]
                    continue

                wire_size = packet_len
                if wire_size % 16 != 0:
                    wire_size = ((packet_len // 16) + 1) * 16

                if len(wire_buffer) < wire_size:
                    block_data = await self.reader.read(4096)
                    if not block_data:
                        break
                    logger.info(f"RAW RECEIVED ({len(block_data)} bytes): {block_data.hex().upper()}")
                    if self.ip:
                        tracer.log("IN", self.ip[0], self.ip[1], block_data)
                    wire_buffer.extend(block_data)
                    continue

                encrypted_packet = bytes(wire_buffer[:wire_size])
                del wire_buffer[:wire_size]
                total_buffer = GBCrypto.decrypt(encrypted_packet, 0)
                header = total_buffer[:4]
                real_payload = total_buffer[4:packet_len]

                logger.info(f"[IN] Recv Packet {hex(packet_id)} from {self.ip} | Len: {packet_len}")
                await handle_packet(self, packet_id, header, real_payload)

        except asyncio.IncompleteReadError:
            logger.info(f"Connection closed by {self.ip}")
        except Exception as e:
            logger.error(f"Error handling client {self.ip}: {e}")
        finally:
            await self.disconnect()

    async def disconnect(self):
        logger.info(f"Disconnecting {self.ip}")
        
        if self.user_id and self.is_authenticated:
            try:
                await self.server.status_manager.user_logout(self.user_id)
            except Exception as e:
                logger.error(f"Error updating status on disconnect: {e}")
            
        
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except:
            pass
        self.server.remove_client(self)

class BuddyServer:
    def __init__(self, host=Config.HOST, port=Config.PORT):
        self.host = host
        self.port = port
        self.server = None
        self.is_running = False
        self.db = Database(Config.DB_CONFIG)
        self.user_sessions = {}
        self.clients = []
        
        # ========== MANAGERS ==========
        self.center_client = None  # BuddyCenter removed; run standalone only
        self.tunneling_manager = TunnelingManager(self)
        self.invite_manager = InviteManager(self)
        self.status_manager = UserStatusManager(self)
        
        # ========== NOVO: P2P MANAGER ==========
        self.p2p_manager = P2PManager(self)

    async def start(self):
        logger.info("="*60)
        logger.info("GUNBOUND BUDDY SERVER - P2P HYBRID EDITION")
        logger.info("="*60)
        
        # Inicializar Database
        logger.info("Initializing Database connection...")
        if not self.db.connect():
             logger.error("Failed to connect to database using Config credentials.")
        
        # ========== INICIAR MANAGERS ==========
        logger.info("Starting Invite Manager...")
        await self.invite_manager.start()
        
        logger.info("Starting User Status Manager...")
        await self.status_manager.start()
        
        # ========== NOVO: INICIA P2P ==========
        logger.info("Starting P2P Manager...")
        await self.p2p_manager.start()
        
        # Iniciar Servidor TCP
        logger.info(f"Starting TCP Server on {Config.HOST}:{Config.PORT}...")
        self.server = await asyncio.start_server(
            self.handle_client, Config.HOST, Config.PORT
        )
        
        addr = self.server.sockets[0].getsockname()
        logger.info('='*60)
        logger.info('🚀 GUNBOUND BUDDY SERVER IS RUNNING (P2P ENABLED)')
        logger.info(f'📡 LISTENING ON: {addr}')
        logger.info('='*60)
        logger.info('✅ Tunneling Manager: Active')
        logger.info('✅ Invite Manager: Active')
        logger.info('✅ Status Manager: Active')
        logger.info('✅ P2P Manager: Active (NEW!)')
        logger.info('✅ BuddyCenter: Disabled (standalone only)')
        logger.info('='*60)
        logger.info('⏳ WAITING FOR GAME CLIENTS/SERVER CONNECTIONS...')
        logger.info('💡 P2P will be used automatically when available')
        logger.info('='*60)

        async with self.server:
            try:
                await self.server.serve_forever()
            except asyncio.CancelledError:
                pass
            
    async def stop(self):
        logger.info("Stopping server...")
        
        # ========== PARAR MANAGERS ==========
        logger.info("Stopping managers...")
        await self.invite_manager.stop()
        await self.status_manager.stop()
        await self.p2p_manager.stop()
        if self.center_client:
            await self.center_client.disconnect()
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        self.db.disconnect()
        logger.info("Server stopped.")

    def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        logger.info(f"⚡ NEW CONNECTION FROM: {addr}")
        client = ClientConnection(reader, writer, self)
        self.clients.append(client)
        asyncio.create_task(client.run())

    def register_user(self, user_id, client):
        self.user_sessions[user_id.lower()] = client
        logger.info(f"✓ User {user_id} registered active session.")

    def get_user_sessions(self, user_id):
        """
        Return all live authenticated sessions for a user.
        Some clients open multiple sockets; routing to only one can miss the UI socket.
        """
        if not user_id:
            return []

        uid_lower = user_id.lower()
        result = []
        seen = set()

        mapped = self.user_sessions.get(uid_lower)
        if mapped and mapped.is_authenticated and not mapped.writer.is_closing():
            result.append(mapped)
            seen.add(id(mapped))

        for c in self.clients:
            if id(c) in seen:
                continue
            if not c or not c.is_authenticated or not c.user_id:
                continue
            if c.user_id.lower() != uid_lower:
                continue
            if c.writer.is_closing():
                continue
            result.append(c)
            seen.add(id(c))

        return result

    def get_user_session(self, user_id):
        sessions = self.get_user_sessions(user_id)
        return sessions[0] if sessions else None

    def unregister_user(self, user_id):
        uid_lower = user_id.lower()
        if uid_lower in self.user_sessions:
            del self.user_sessions[uid_lower]
            logger.info(f"✗ User {user_id} session unregistered.")

    def remove_client(self, client):
        if client in self.clients:
            self.clients.remove(client)
        if client.user_id:
            self.unregister_user(client.user_id)
    
    # ========== MÉTODOS AUXILIARES PARA STATS ==========
    
    def get_server_stats(self):
        """Retorna estatísticas completas do servidor"""
        return {
            'server': {
                'online_users': len(self.user_sessions),
                'total_connections': len(self.clients),
                'uptime': 0
            },
            'center': {},
            'tunneling': self.tunneling_manager.get_stats(),
            'invites': self.invite_manager.get_stats(),
            'status': self.status_manager.get_stats(),
            'p2p': self.p2p_manager.get_stats()  # NOVO
        }
    
    def print_stats(self):
        """Imprime estatísticas no console"""
        stats = self.get_server_stats()
        
        print("\n" + "="*60)
        print("📊 SERVER STATISTICS (P2P ENABLED)")
        print("="*60)
        print(f"👥 Online Users: {stats['server']['online_users']}")
        print(f"🔌 Active Connections: {stats['server']['total_connections']}")
        
        # ========== NOVO: STATS P2P ==========
        print("\n--- P2P Stats ---")
        p2p = stats['p2p']
        print(f"🔗 P2P Attempts: {p2p['p2p_attempts']}")
        print(f"✅ Successful: {p2p['p2p_successful']}")
        print(f"📊 Success Rate: {p2p['success_rate']}")
        print(f"🟢 Active P2P: {p2p['active_p2p_connections']}")
        print(f"📦 Relay Mode: {p2p['relay_mode_connections']}")
        
        print("\n--- Tunneling ---")
        print(f"📦 Total Tunneled: {stats['tunneling']['total_tunneled']}")
        print(f"✅ Success Rate: {stats['tunneling']['success_rate']}")
        print(f"💾 Offline Saved: {stats['tunneling']['offline_saved']}")
        
        print("\n--- Invites ---")
        print(f"📨 Total Sent: {stats['invites']['total_sent']}")
        print(f"✅ Accepted: {stats['invites']['total_accepted']}")
        print(f"❌ Rejected: {stats['invites']['total_rejected']}")
        print(f"⏰ Active: {stats['invites']['active_invites']}")
        
        print("\n--- Status ---")
        print(f"🟢 Online: {stats['status']['status_distribution'].get('ONLINE', 0)}")
        print(f"🎮 In Game: {stats['status']['status_distribution'].get('IN_GAME', 0)}")
        print(f"💤 Away: {stats['status']['status_distribution'].get('AWAY', 0)}")
        print("="*60 + "\n")
