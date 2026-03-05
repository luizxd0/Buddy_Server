import os
import logging
import binascii
import time
import traceback
import struct
from .constants import *
from .packets import Packet, PacketBuilder, PacketReader
from .crypto import GBCrypto, KEY_GAME_STATIC_HEX, KEY_STATIC_HEX
from .config import Config

logger = logging.getLogger(__name__)

META_2021_TEMPLATE = binascii.unhexlify("51c0180012008d02d007d300ffff0000ffff36034800000000008d02")

def _enc_fixed(value, size):
    return value.encode('latin-1', errors='ignore')[:size].ljust(size, b'\x00')

def _build_meta_2021(status):
    """
    Fallback 0x2021 metadata (28 bytes). Real clients send richer meta in 0x2020 status
    updates; when available we cache and reuse those exact bytes.
    """
    meta = bytearray(META_2021_TEMPLATE)
    struct.pack_into('<H', meta, 4, status & 0xFFFF)
    return bytes(meta)


def _meta_with_status(meta, status):
    m = bytearray(meta)
    struct.pack_into('<H', m, 4, status & 0xFFFF)
    return bytes(m)


def _get_cached_meta_2021(server, user_id):
    sm = getattr(server, "status_manager", None)
    if not sm:
        return None
    try:
        data = sm.get_status_data(user_id) or {}
    except Exception:
        return None
    meta = data.get("meta_2021")
    if isinstance(meta, (bytes, bytearray)) and len(meta) == 28:
        return bytes(meta)
    return None


def _cache_meta_2021(server, user_id, meta):
    if not isinstance(meta, (bytes, bytearray)) or len(meta) != 28:
        return
    sm = getattr(server, "status_manager", None)
    if not sm:
        return
    if user_id not in sm.user_status_data:
        sm.user_status_data[user_id] = {}
    sm.user_status_data[user_id]["meta_2021"] = bytes(meta)


def _resolve_canonical_user_id(server, raw_id):
    if not raw_id:
        return ""
    candidate = raw_id.strip()
    if not candidate:
        return ""

    data = server.db.get_user_game_data(candidate) or server.db.get_user_by_nickname(candidate)
    if data:
        return data.get("UserId") or data.get("Id") or candidate

    for uid in server.user_sessions.keys():
        if uid.lower() == candidate.lower():
            return uid

    return candidate


def _users_are_buddies(server, user_a, user_b):
    if not user_a or not user_b:
        return False
    a = user_a.lower()
    b = user_b.lower()
    try:
        buddies = server.db.get_full_buddy_list(user_a) or []
        for item in buddies:
            fid = (item.get("Id") or item.get("FriendId") or item.get("friend_id") or "").strip()
            if fid and fid.lower() == b:
                return True
    except Exception:
        return False
    return False


def _mark_recent_buddy_removal(server, user_a, user_b):
    if not user_a or not user_b:
        return
    cache = getattr(server, "recent_buddy_removals", None)
    if cache is None:
        cache = {}
        setattr(server, "recent_buddy_removals", cache)
    key = tuple(sorted((user_a.lower(), user_b.lower())))
    now = time.time()
    cache[key] = now
    # Keep cache tiny and fresh.
    for k, ts in list(cache.items()):
        if now - ts > 15.0:
            del cache[k]


def _was_recent_buddy_removal(server, user_a, user_b, window_seconds=8.0):
    if not user_a or not user_b:
        return False
    cache = getattr(server, "recent_buddy_removals", None)
    if not cache:
        return False
    key = tuple(sorted((user_a.lower(), user_b.lower())))
    ts = cache.get(key)
    if ts is None:
        return False
    if time.time() - ts <= window_seconds:
        return True
    del cache[key]
    return False


def _mark_recent_buddy_request(server, sender_user_id, target_user_id):
    if not sender_user_id or not target_user_id:
        return
    cache = getattr(server, "recent_buddy_requests", None)
    if cache is None:
        cache = {}
        setattr(server, "recent_buddy_requests", cache)
    now = time.time()
    key = (sender_user_id.lower(), target_user_id.lower())
    cache[key] = now
    for k, ts in list(cache.items()):
        if now - ts > 45.0:
            del cache[k]


def _was_recent_buddy_request(server, sender_user_id, target_user_id, window_seconds=30.0):
    if not sender_user_id or not target_user_id:
        return False
    cache = getattr(server, "recent_buddy_requests", None)
    if not cache:
        return False
    key = (sender_user_id.lower(), target_user_id.lower())
    ts = cache.get(key)
    if ts is None:
        return False
    if time.time() - ts <= window_seconds:
        return True
    del cache[key]
    return False


def _should_process_buddy_43(server, actor_user_id, target_user_id, window_seconds=1.0):
    """
    Throttle repeated ambiguous 0x43 actions from the same pair to avoid
    delete/reject feedback loops and log storms.
    """
    if not actor_user_id or not target_user_id:
        return True
    cache = getattr(server, "recent_buddy_43", None)
    if cache is None:
        cache = {}
        setattr(server, "recent_buddy_43", cache)

    now = time.time()
    key = (actor_user_id.lower(), target_user_id.lower())
    ts = cache.get(key)
    if ts is not None and (now - ts) <= window_seconds:
        return False

    cache[key] = now
    for k, t in list(cache.items()):
        if now - t > 10.0:
            del cache[k]
    return True


def _should_emit_buddy_decision(server, actor_user_id, target_user_id, is_accept, window_seconds=2.0):
    """
    Deduplicate accept/reject popups emitted through multiple protocol paths
    (commonly both 0x3000 and 0x2020 for the same user action).
    """
    if not actor_user_id or not target_user_id:
        return True
    cache = getattr(server, "recent_buddy_decisions", None)
    if cache is None:
        cache = {}
        setattr(server, "recent_buddy_decisions", cache)

    now = time.time()
    key = (actor_user_id.lower(), target_user_id.lower(), 1 if is_accept else 0)
    ts = cache.get(key)
    if ts is not None and (now - ts) <= window_seconds:
        return False

    cache[key] = now
    for k, t in list(cache.items()):
        if now - t > 10.0:
            del cache[k]
    return True

async def handle_packet(client, packet_id, header, payload):
    reader = PacketReader(payload)
    
    if packet_id == SVC_LOGIN_REQ:
        await handle_login(client, reader)
    elif packet_id == SVC_LOGIN_DATA:
        await handle_login(client, reader)
    elif packet_id == SVC_ADD_BUDDY:
        await handle_add_buddy(client, reader)
    elif packet_id == SVC_REMOVE_BUDDY:
        await handle_remove_buddy(client, reader)
    elif packet_id == SVC_GROUP_BUDDY:
        await handle_group_buddy(client, reader)
    elif packet_id == SVC_RENAME_GROUP:
        await handle_rename_group(client, reader)
    elif packet_id == SVC_USER_STATE:
        await handle_user_state(client, reader)
    elif packet_id == SVC_SEARCH:
        await handle_search(client, reader)
    elif packet_id == SVC_TUNNEL_PACKET:
        await handle_tunnel_packet(client, reader)
    elif packet_id == 0x2000:  # Legacy save/chat packet from some clients
        await handle_save_packet_2000(client, payload)
    elif packet_id == 0xA110: # Chat Message
        await handle_buddy_chat(client, payload)
    elif packet_id == 0xA200: # Add Buddy / Invite / Relay
        await handle_buddy_action(client, payload)
    elif packet_id == BUDDY_ACTION_ACCEPT_REJECT:  # 0x3000
        await handle_buddy_accept_reject_3000(client, PacketReader(payload))
    elif packet_id == 0xA510: # Status Update
        await handle_client_status_update(client, PacketReader(payload))
    elif packet_id == 0xA502 or packet_id == 0xA500: # Heartbeat
        await handle_heartbeat(client, PacketReader(payload))
    elif packet_id == 0x1030: # Buddy Note
        await handle_buddy_note(client, PacketReader(payload))
    elif packet_id == 0xA000: # BUDDY_LOGIN
        await handle_buddy_login(client, PacketReader(payload))
    
    # ========== HANDLERS INVITE SYSTEM ==========
    elif packet_id == 0xA300:  # Send Invite
        await handle_send_invite(client, PacketReader(payload))
    elif packet_id == 0xA302:  # Accept Invite
        await handle_accept_invite(client, PacketReader(payload))
    elif packet_id == 0xA303:  # Reject Invite
        await handle_reject_invite(client, PacketReader(payload))
    elif packet_id == 0xA304:  # Cancel Invite
        await handle_cancel_invite(client, PacketReader(payload))
    
    # ========== HANDLERS STATUS SYSTEM ==========
    elif packet_id == 0xA511:  # Status Query
        await handle_status_query(client, PacketReader(payload))
    
    # ========== HANDLERS GAME INTEGRATION ==========
    elif packet_id == 0xB100:  # Enter Game
        await handle_enter_game(client, PacketReader(payload))
    elif packet_id == 0xB101:  # Leave Game
        await handle_leave_game(client, PacketReader(payload))
    
    # ========== NOVOS HANDLERS P2P ==========
    elif packet_id == 0xC000:  # PKT_P2P_REQUEST
        await handle_p2p_request(client, PacketReader(payload))
    elif packet_id == 0xC002:  # PKT_P2P_ANSWER
        await handle_p2p_answer(client, PacketReader(payload))
    
    # ========== HANDLERS SERVER/BROKER (Infrastructure) ==========
    # IDs baseados na anÃ¡lise do binÃ¡rio GunBoundBroker3.exe
    elif packet_id == 0x3000 or packet_id == 0x3010: # SVC_CMD_SETVERSION / STATUS match
         # Broker muitas vezes usa ranges 0x3xxx ou similares para comandos internos
         # Precisamos checar o dump para IDs exatos se soubermos, mas vamos logar e aceitar
         logger.info(f"âš¡ [SERVER COMMAND] Recebido possÃ­vel comando de servidor: {hex(packet_id)}")
         
    # Se receber SVC_CMD_SETVERSION (geralmente troca de versÃ£o)
    elif packet_id == 0x6be9c: # Visto no dump como SVC_CMD_SETVERSION (offset, nÃ£o ID)
         pass # Placeholder, offsets != IDs
    
    # Comandos genÃ©ricos de servidor que podem aparecer
    elif packet_id in [0xA0F0, 0xA0F1, 0xA0F2]: # Exemplo de IDs de Admin
         logger.info(f"ðŸ”§ [ADMIN/SERVER] Command {hex(packet_id)} accepted from {client.ip}")
         
    else:
        # Se vier de localhost e for desconhecido, 99% de chance de ser o Broker ou GameServer
        if client.ip and client.ip[0] == '127.0.0.1':
             logger.warning(f"âš ï¸ [BROKER/SERVER?] Packet {hex(packet_id)} from LOCALHOST ({client.ip[1]}) not handled!")
             logger.warning(f"   Payload Hex: {payload.hex()[:50]}...")
        else:
             logger.warning(f"Unknown or Unhandled Packet ID: {hex(packet_id)} from {client.ip}")

# ============================================================================
# NOVOS HANDLERS P2P
# ============================================================================

async def handle_p2p_request(client, reader):
    """Cliente solicita estabelecer conexÃ£o P2P com outro usuÃ¡rio"""
    try:
        target_id = reader.read_string()
        
        logger.info(f"[P2P REQUEST] {client.user_id} wants P2P with {target_id}")
        
        success = await client.server.p2p_manager.request_p2p(client, target_id)
        
        if success:
            logger.info(f"âœ… [P2P] Negotiation started: {client.user_id} <-> {target_id}")
        else:
            logger.warning(f"âš ï¸ [P2P] Failed to start negotiation")
            
    except Exception as e:
        logger.error(f"âŒ [P2P REQUEST ERROR] {e}")
        import traceback
        logger.error(traceback.format_exc())

async def handle_p2p_answer(client, reader):
    """Cliente responde se conseguiu estabelecer P2P"""
    try:
        await client.server.p2p_manager.handle_p2p_answer(client, reader.data)
    except Exception as e:
        logger.error(f"âŒ [P2P ANSWER ERROR] {e}")

# ============================================================================
# CHAT HANDLER - AGORA USA P2P QUANDO DISPONÃVEL
# ============================================================================

async def handle_save_packet_2000(client, payload):
    """
    Some clients send message packets as 0x2000. When payload matches legacy chat
    shape (target\\0 + metadata + body), handle it through the same chat path.
    """
    try:
        if not payload:
            return
        if b'\x00' in payload:
            await handle_buddy_chat(client, payload)
            return
        logger.warning(f"[0x2000] Unparsed save/chat payload ({len(payload)} bytes). Hex(first64)={payload[:64].hex()}")
    except Exception as e:
        logger.error(f"[0x2000] Error: {e}")

async def handle_buddy_chat(client, payload):
    """
    Chat relay in official 0x2021 message format:
      UID(16) + Nick(12) + 11 C0 1F 00 + Message(40)
    """
    try:
        if not client.is_authenticated or not client.user_id:
            logger.warning(f"[CHAT] Ignored unauthenticated chat packet from {client.ip}")
            return

        if b'\x00' not in payload:
            logger.warning("[CHAT] Invalid payload: missing target separator")
            return

        target_raw, remainder = payload.split(b'\x00', 1)
        target_id = target_raw.decode('latin-1', errors='ignore').strip()
        if not target_id:
            logger.warning("[CHAT] Invalid payload: empty target")
            return

        # Legacy client format carries 9 bytes metadata before message body.
        message_data = remainder[9:] if len(remainder) >= 9 else b""
        while message_data and message_data[0] == 0:
            message_data = message_data[1:]

        target_id = _resolve_canonical_user_id(client.server, target_id)
        if not target_id:
            logger.warning("[CHAT] Failed to resolve target user")
            return

        sender_data = client.server.db.get_user_game_data(client.user_id) or {}
        sender_nick = sender_data.get("NickName") or client.user_id

        msg = message_data.split(b'\x00', 1)[0]
        msg = msg[:39] + b'\x00'
        msg = msg.ljust(40, b'\x00')

        chat_payload_2021 = (
            _enc_fixed(client.user_id, 16)
            + _enc_fixed(sender_nick, 12)
            + b'\x11\xC0\x1F\x00'
            + msg
        )

        ok = await client.server.tunneling_manager.send_buddy_request_to_client(
            client,
            target_id,
            chat_payload_2021,
            allow_offline_store=True,
        )
        if ok:
            logger.info(f"[CHAT] Relayed/stored chat: {client.user_id} -> {target_id}")
        else:
            logger.warning(f"[CHAT] Failed to relay chat: {client.user_id} -> {target_id}")
    except Exception as e:
        logger.error(f"[CHAT] Error handling chat: {e}")

# ============================================================================
# BUDDY ACTION HANDLER - COM P2P
# ============================================================================

async def handle_buddy_action(client, payload):
    """
    Handler genÃ©rico para Buddy Actions (Convites, etc).
    Atua como Relay Transparente: Recebe -> Repassa para o Alvo.
    """
    try:
        logger.debug(f"[BUDDY ACTION DEBUG] Payload ({len(payload)} bytes): {payload.hex()}")
        
        if b'\x00' not in payload:
            logger.error("[BUDDY ACTION] Payload invÃ¡lido: sem null terminator")
            return
        
        parts = payload.split(b'\x00', 1)
        target_id_raw = parts[0]
        target_id = target_id_raw.decode('latin-1', errors='ignore').strip()
        
        if not target_id:
            logger.error("[BUDDY ACTION] Target ID vazio!")
            return

        logger.info(f"[BUDDY ACTION] {client.user_id} -> {target_id}")
        
        # ReconstrÃ³i payload padrÃ£o: SENDER + NULL + RESTO
        # O cliente original espera ver quem mandou no inÃ­cio do pacote
        remainder = parts[1]
        
        sender_bytes = client.user_id.encode('latin-1')
        
        output_payload = bytearray()
        output_payload.extend(sender_bytes)
        output_payload.append(0)
        output_payload.extend(remainder)
        
        # ========== VERIFICA TARGET ==========
        target_session = _get_session_by_user_id(client.server, target_id)
        
        if not target_session:
            logger.warning(f"[BUDDY ACTION] Target {target_id} offline ou nÃ£o encontrado")
            # If it was an acceptance (0x02), we should still update DB if possible? 
            # No, let's keep it real-time for now.
            return
            
        # EXTRA: If this is an Acceptance packet (often status 0x02 or similar)
        # We should update our database because BOTH users now agreed.
        if len(remainder) > 0:
            action_type = remainder[0]
            if action_type == 0x02: # ACCEPT
                logger.info(f"[BUDDY] {client.user_id} accepted invitation from {target_id}. Updating DB.")
                client.server.db.add_buddy(client.user_id, target_id)
                client.server.db.add_buddy(target_id, client.user_id)
            elif action_type == 0x03: # REJECT
                logger.info(f"[BUDDY] {client.user_id} rejected invitation from {target_id}.")
            
        # ========== TENTA VIA P2P SE DISPONÃVEL ==========
        p2p_available = client.server.p2p_manager.should_use_p2p(client.user_id, target_id)
        
        if p2p_available:
            logger.info(f"[BUDDY ACTION] ðŸ”— Tentando via P2P...")
            success = await client.server.p2p_manager.send_via_p2p(
                client.user_id,
                target_id,
                0xA200, # MantÃ©m ID original
                bytes(output_payload)
            )
            if success:
                logger.info("âœ… [BUDDY ACTION] Enviado via P2P")
                return

        # ========== FALLBACK: RELAY DIRETO ==========
        logger.info("[BUDDY ACTION] Usando Relay do Servidor...")
        
        out_pkt = PacketBuilder(0xA200)
        out_pkt.buffer = bytearray(output_payload)
        
        await target_session.send_packet(out_pkt.build())
        logger.info(f"âœ… [BUDDY ACTION RELAY] {client.user_id} -> {target_id} enviado.")

    except Exception as e:
        logger.error(f"âŒ [BUDDY ACTION ERROR] {e}")
        import traceback
        logger.error(traceback.format_exc())

def _get_session_by_user_id(server, user_id):
    """Resolve the best live session for a user."""
    if not user_id:
        return None
    if hasattr(server, "get_user_session"):
        return server.get_user_session(user_id)
    return server.user_sessions.get(user_id.lower())

async def _send_buddy_decision_popup(server, target_session, actor_user_id, is_accept):
    """
    Send legacy short 0x2021 decision event expected by the requester UI:
    UID(16) + Nick(12) + Marker(5), where marker is:
      - accept: 42 C0 01 00 01
      - reject: 42 C0 01 00 00
    (based on fresh captures in packets_add_and_accept/reject).
    """
    actor_data = server.db.get_user_game_data(actor_user_id) or {}
    actor_uid = _enc_fixed(actor_user_id, 16)
    actor_nick = _enc_fixed(actor_data.get('NickName') or actor_user_id, 12)
    marker = b'\x42\xC0\x01\x00\x01' if is_accept else b'\x42\xC0\x01\x00\x00'

    evt = PacketBuilder(SVC_RELAY_BUDDY_REQ)
    evt.write_bytes(actor_uid)
    evt.write_bytes(actor_nick)
    evt.write_bytes(marker)
    await target_session.send_packet(evt.build())


async def _send_buddy_removed_popup(server, target_session, actor_user_id):
    """
    Send legacy short 0x2021 remove event expected by some clients to update
    buddy UI immediately (without requiring world-list/channel reload).
    Layout: UID(16) + Nick(12) + Marker(5)
    Marker: 43 C0 01 00 01
    """
    try:
        actor_data = server.db.get_user_game_data(actor_user_id) or {}
        actor_uid = _enc_fixed(actor_user_id, 16)
        actor_nick = _enc_fixed(actor_data.get('NickName') or actor_user_id, 12)
        marker = b'\x43\xC0\x01\x00\x01'

        evt = PacketBuilder(SVC_RELAY_BUDDY_REQ)
        evt.write_bytes(actor_uid)
        evt.write_bytes(actor_nick)
        evt.write_bytes(marker)
        await target_session.send_packet(evt.build())
    except Exception as e:
        logger.warning(f"[0x3002] Failed to send live remove popup to target: {e}")


async def handle_buddy_accept_reject_3000(client, reader):
    """
    Official 0x3000: Recipient accepts/rejects. 
    Layout: 16b Nick/ID + padding + action.
    """
    try:
        raw = reader.data or b""
        if len(raw) < 21:
            return
            
        target_name = raw[:16].rstrip(b'\x00').decode('latin-1', errors='ignore').strip()
        
        # 0x3000 is ambiguous in this protocol variant: byte 0x01 appears in both paths.
        # Prefer explicit decision bytes to avoid false-accept on reject.
        action = None
        for idx in range(16, min(len(raw), 32)):
            b = raw[idx]
            if b in (0x02, 0x03):
                action = b
                break

        # Fallback observed in captures: marker 42 C0 01 00 XX
        #   XX=01 -> accept, XX=00 -> reject
        # We still only accept an explicit marker, not a generic 0x01 byte.
        if action is None:
            marker = b"\x42\xC0\x01\x00"
            marker_pos = raw.find(marker)
            if marker_pos != -1 and marker_pos + len(marker) < len(raw):
                flag = raw[marker_pos + len(marker)]
                if flag == 0x01:
                    action = 0x02
                elif flag == 0x00:
                    action = 0x03
        
        if action is None:
            logger.info(
                f"[0x3000] Ambiguous action for {client.user_id} -> '{target_name}' (no explicit 0x02/0x03). "
                f"Ignoring 0x3000 to avoid false accept. Raw={raw.hex().upper()}"
            )
            return
        
        is_accept = (action == 0x02)
        logger.info(f"[0x3000] Buddy Action: {client.user_id} -> '{target_name}', action={action:#02x}, accept={is_accept}")
        
        target_data = client.server.db.get_user_game_data(target_name)
        if not target_data:
            target_data = client.server.db.get_user_by_nickname(target_name)
        
        if not target_data:
            logger.warning(f"[0x3000] Could not resolve target: '{target_name}'")
            return
            
        target_id = target_data.get('UserId') or target_data.get('Id')
        
        if is_accept:
            # 1. Update Database IMMEDIATELY
            client.server.db.add_buddy(client.user_id, target_id)
            client.server.db.add_buddy(target_id, client.user_id)
            logger.info(f"Mutual buddy added: {client.user_id} <-> {target_id}")
            
            # 2. Refresh for Recipient (us)
            await send_friend_list(client)
        
        # 3. Notify Sender (them)
        sender_session = _get_session_by_user_id(client.server, target_id)
        if sender_session:
            my_game_data = client.server.db.get_user_game_data(client.user_id) or {}
            my_nick = my_game_data.get('NickName') or client.user_id
            my_guild = my_game_data.get('Guild') or ""
            
            # Standard Acceptance Relay (60 bytes total / 56 bytes payload)
            # Layout: UID(16) + Nick(12) + Metadata(28)
            uid_b = _enc_fixed(client.user_id, 16)
            nick_b_12 = _enc_fixed(my_nick, 12)
            guild_b = _enc_fixed(my_guild, 8)
            
            if is_accept:
                # Ensure requester gets the same accept popup used in 0x2020 accept path.
                if _should_emit_buddy_decision(client.server, client.user_id, target_id, True):
                    await _send_buddy_decision_popup(
                        client.server,
                        sender_session,
                        client.user_id,
                        is_accept=True,
                    )
                else:
                    logger.debug(f"[DEDUP] Suppressed duplicate accept popup: {client.user_id} -> {target_id}")

                cached_meta = _get_cached_meta_2021(client.server, client.user_id)
                meta = cached_meta if cached_meta else _build_meta_2021(0x0012)
                evt = PacketBuilder(SVC_RELAY_BUDDY_REQ)
                evt.write_bytes(uid_b)
                evt.write_bytes(nick_b_12)
                evt.write_bytes(meta)
                await sender_session.send_packet(evt.build())
            else:
                if _should_emit_buddy_decision(client.server, client.user_id, target_id, False):
                    await _send_buddy_decision_popup(
                        client.server,
                        sender_session,
                        client.user_id,
                        is_accept=False,
                    )
                else:
                    logger.debug(f"[DEDUP] Suppressed duplicate reject popup: {client.user_id} -> {target_id}")
            
            if is_accept:
                # Also send the 0x3001 packet to ensure it appears in the list immediately
                rank_icon = int(my_game_data.get('TotalRank') or 0)
                add_resp = PacketBuilder(SVC_ADD_BUDDY_RESP)
                add_resp.write_short(0)
                add_resp.write_bytes(uid_b)
                add_resp.write_bytes(nick_b_12)
                add_resp.write_bytes(guild_b)
                add_resp.write_short(rank_icon & 0xFFFF)
                await sender_session.send_packet(add_resp.build())
                
                await send_friend_list(sender_session)
                # await send_user_status_update(sender_session, client.user_id, 0x0012)
                
        # 4. Final Sync for Recipient (Exactly 35 bytes)
        sync = PacketBuilder(SVC_USER_SYNC)
        sync.write_short(0x0100) # Prefix
        my_nick_val = (client.server.db.get_user_game_data(client.user_id) or {}).get('NickName') or client.user_id
        sync.write_bytes(my_nick_val.encode('latin-1')[:15].ljust(16, b'\x00'))
        sync.write_bytes(binascii.unhexlify("0133bfabea000033bfabea0000"))
        await client.send_packet(sync.build())

    except Exception as e:
        logger.error(f"[0x3000] Critical Error: {e}")
        traceback.print_exc()

    except Exception as e:
        logger.error(f"[0x3000] Critical Error: {e}")
        traceback.print_exc()

async def send_user_status_update(client, buddy_id, status_code):
    """Refined 0x3011 layout for status updates: UID(16) + Nick(16) + Status(2)"""
    try:
        buddy_data = client.server.db.get_user_game_data(buddy_id) or {}
        nick = (buddy_data.get('NickName') or buddy_id).encode('latin-1', errors='ignore')[:15].ljust(16, b'\x00')
        uid = buddy_id.encode('latin-1', errors='ignore')[:15].ljust(16, b'\x00')
        
        pkt = PacketBuilder(SVC_USER_STATE)
        pkt.write_bytes(uid)
        pkt.write_bytes(nick)
        pkt.write_short(status_code)
        await client.send_packet(pkt.build())
    except Exception as e:
        logger.error(f"Error sending status update: {e}")


# ============================================================================
# OUTROS HANDLERS (mantidos do original)
# ============================================================================

async def handle_client_status_update(client, reader):
    """Handler de status com validaÃ§Ã£o."""
    try:
        await client.server.status_manager.user_activity(client.user_id)
        await client.server.status_manager.handle_status_update_packet(client, reader.data)
    except Exception as e:
        logger.error(f"Error in status update: {e}")

async def handle_heartbeat(client, reader):
    """Handler de heartbeat."""
    try:
        await client.server.status_manager.user_activity(client.user_id)
        
        ack = PacketBuilder(0xA500)
        await client.send_packet(ack.build())
    except Exception as e:
        logger.error(f"Error in heartbeat: {e}")

async def handle_buddy_note(client, reader):
    logger.info("Buddy Note (0x1030) packet received - Not implemented yet")

async def send_fake_online_notification(client, fake_user_id, fake_nick):
    resp = PacketBuilder(0x1010)
    resp.write_int(1)
    
    resp.write_string(fake_nick)
    resp.write_byte(1)
    resp.write_string(fake_user_id)
    resp.write_int(0)
    
    await client.send_packet(resp.build())
    logger.info(f"Faked {fake_user_id} as ONLINE to {client.user_id}")

async def handle_buddy_login(client, reader):
    """Handler de login."""
    try:
        version = reader.read_int()
        
        raw_data = reader.data
        version_again = int.from_bytes(raw_data[:4], 'little')
        
        str_data = raw_data[4:]
        if b'\x00' in str_data:
            user_id = str_data.split(b'\x00')[0].decode('latin-1')
        else:
            user_id = str_data.decode('latin-1')
            
    except Exception as e:
        logger.error(f"Error parsing Buddy Login: {e}")
        return

    logger.info(f"BUDDY LOGIN SUCCESS: User={user_id} (Ver={version})")
    client.user_id = user_id
    client.is_authenticated = True
    client.server.register_user(user_id, client)
    
    await client.server.status_manager.user_login(user_id)
    
    # BuddyCenter removed; no cross-server notify
    
    resp_ack = PacketBuilder(SVC_LOGIN_RESP)
    resp_ack.write_int(1)
    await client.send_packet(resp_ack.build())
    logger.info(f"Sent Login Success (0x1001) to {user_id}")

    await send_friend_list(client)

    import asyncio
    await asyncio.sleep(1.0)
    await client.server.tunneling_manager.deliver_offline_tunnels(client)

    buddies_raw = client.server.db.get_buddy_list(client.user_id)
    if buddies_raw:
        friend_ids = [b.get('friend_id', b.get('FriendId')) for b in buddies_raw if b.get('friend_id') or b.get('FriendId')]
        for fid in friend_ids:
            f_sess = client.server.user_sessions.get(fid.lower())
            if f_sess:
                await send_friend_list(f_sess)
                logger.info(f"Notified {fid} that {client.user_id} is online")



async def send_friend_list(client):
    """
    Official 0x1011 (Buddy List).
    Strategy: Send one 32-byte packet per buddy.
    Payload (32b): Nickname (16) + UserID (12) + Status (2) + Grade (2).
    """
    try:
        buddies_raw = client.server.db.get_full_buddy_list(client.user_id)
        if not buddies_raw:
            logger.info(f"User {client.user_id} has no buddies. Sending empty 0x1011.")
            # Explicit empty buddy-list packet. Some clients keep buddy UI inactive
            # until they receive this plus the following sync packet.
            empty_list = PacketBuilder(SVC_BUDDY_LIST)
            await client.send_packet(empty_list.build())

            sync_pkt = PacketBuilder(SVC_USER_SYNC)
            sync_pkt.write_short(0x0100)
            my_data = client.server.db.get_user_game_data(client.user_id) or {}
            my_nick = my_data.get('NickName') or client.user_id
            sync_pkt.write_bytes(my_nick.encode('latin-1')[:15].ljust(16, b'\x00'))
            sync_pkt.write_bytes(binascii.unhexlify("0133bfabea000033bfabea0000"))
            await client.send_packet(sync_pkt.build())
            return

        for b in buddies_raw:
            # Robustly resolve buddy ID
            friend_id = b.get('FriendId') or b.get('friend_id') or b.get('Id')
            if not friend_id:
                logger.warning(f"Skipping buddy entry with no ID: {b}")
                continue

            is_online = (friend_id.lower() in client.server.user_sessions)
            guild_name = b.get('Guild') or ""
            
            nick_val = b.get('NickName') or friend_id
            uid_b = _enc_fixed(friend_id, 16)
            nick_b_12 = _enc_fixed(nick_val, 12)
            guild_b = _enc_fixed(guild_name, 8)

            # 1. 0x3001 (SVC_ADD_BUDDY_RESP) - 44 bytes total (4 header + 40 payload)
            # Layout observed: Prefix(2) + UID(16) + Nick(12) + Guild(8) + RankIcon(2)
            add_resp = PacketBuilder(SVC_ADD_BUDDY_RESP)
            add_resp.write_short(0)
            add_resp.write_bytes(uid_b)
            add_resp.write_bytes(nick_b_12)
            add_resp.write_bytes(guild_b)
            cached_meta = _get_cached_meta_2021(client.server, friend_id)
            if cached_meta:
                if is_online:
                    meta = cached_meta
                    status = struct.unpack_from('<H', cached_meta, 4)[0]
                else:
                    status = 0
                    meta = _meta_with_status(cached_meta, 0)
            else:
                status = client.server.status_manager.get_gunbound_status_bitmask(friend_id) if is_online else 0
                meta = _build_meta_2021(status)
            rank_icon = int(b.get('TotalRank') or 0)

            # 0. 0x1011 (SVC_BUDDY_LIST) - keep official login bootstrap semantics.
            # Payload (32): Nick(16) + UID(12) + Status(2) + Grade(2)
            # Some clients only enable immediate buddy actions after receiving non-empty 0x1011 entries.
            list_pkt = PacketBuilder(SVC_BUDDY_LIST)
            list_pkt.write_bytes(_enc_fixed(nick_val, 16))
            list_pkt.write_bytes(_enc_fixed(friend_id, 12))
            list_pkt.write_short(status & 0xFFFF)
            grade_val = int(b.get('TotalGrade') or b.get('TotalRank') or 0)
            list_pkt.write_short(grade_val & 0xFFFF)
            await client.send_packet(list_pkt.build())

            add_resp.write_short(rank_icon & 0xFFFF)
            await client.send_packet(add_resp.build())

            # 2. 0x2021 (SVC_RELAY_BUDDY_REQ) - 60 bytes total (4 header + 56 payload)
            # Observed layout: UID(16) + Nick(12) + Meta(28)
            
            relay_upd = PacketBuilder(SVC_RELAY_BUDDY_REQ)
            relay_upd.write_bytes(uid_b)
            relay_upd.write_bytes(nick_b_12)
            relay_upd.write_bytes(meta)
            
            final_pkt = relay_upd.build()
            await client.send_packet(final_pkt)
            
            logger.info(f"Relayed Buddy Info (0x2021) v20: UID={friend_id}, Nick={nick_val}, Guild='{guild_name}', Online={is_online}, Status={status}")
            logger.debug(f"[0x2021 HEX] {final_pkt.to_bytes().hex().upper()}")
        
        # Followed by 35-byte Sync (0x3FFF)
        sync_pkt = PacketBuilder(SVC_USER_SYNC)
        sync_pkt.write_short(0x0100)
        my_data = client.server.db.get_user_game_data(client.user_id) or {}
        my_nick = my_data.get('NickName') or client.user_id
        sync_pkt.write_bytes(my_nick.encode('latin-1')[:15].ljust(16, b'\x00'))
        sync_pkt.write_bytes(binascii.unhexlify("0133bfabea000033bfabea0000")) 
        await client.send_packet(sync_pkt.build())
        
    except Exception as e:
        logger.error(f"Error in send_friend_list: {e}")
        import traceback
        logger.error(traceback.format_exc())

async def handle_login(client, reader):
    # Protocol (README): Length | Opcode | Payload. Client may send 0x1000 with no payload first,
    # then wait for 0x1001 before sending user_id in a second packet. If we don't respond, client
    # blocks and never sends the next packet (deadlock). So we send 0x1001(1) to unblock the client.
    if not reader.has_data():
        # Align with Java game server: 0x1001 payload = 4-byte auth token (client uses it for 0x1010 key derivation)
        client.auth_token = os.urandom(4)
        logger.info(
            "Login 0x1000 with empty payload; sending 0x1001 with 4-byte auth token (Java-aligned). Token=%s (for RE: use with re_1010_login.py)",
            client.auth_token.hex(),
        )
        resp = PacketBuilder(SVC_LOGIN_RESP)
        resp.write_bytes(bytes(client.auth_token))
        await client.send_packet(resp.build())
        return

    raw = reader.data if reader.data else b""
    user_id_req = None

    if raw and len(raw) >= 16:
        # Treat as encrypted 0x1010 payload; do not use raw.decode() as username. Resolve only via decrypt + game table.
        def _accept_only_if_in_game(s: str):
            """Set user_id_req only if s is a valid UserId/NickName in game table (avoids accepting decrypted garbage)."""
            if not s or not s.strip() or len(s) > 32 or not s.isprintable():
                return False
            if any(c in s for c in '\x00\r\n'):
                return False
            if client.server.db.get_user_game_data(s.strip()):
                nonlocal user_id_req
                user_id_req = s.strip()
                return True
            return False

        # 1) Java-style: first 16 bytes with FIXED_KEY (same as game server LoginReader).
        try:
            username_block = GBCrypto.decrypt_game_static(raw[0:16])
            # Find the first null byte and truncate to ignore garbage/padding
            end = username_block.find(b'\x00')
            clean_block = username_block[:end] if end >= 0 else username_block
            s = clean_block.decode('utf-8', errors='ignore').strip()
            if _accept_only_if_in_game(s):
                logger.info("0x1010 username resolved via Java-style static decrypt (FIXED_KEY): %s", user_id_req)
        except Exception:
            pass

        # 1.5) Buddy-specific static key extracted from 0x5516b4
        if not user_id_req or not user_id_req.isprintable():
            try:
                buddy_block = GBCrypto.decrypt_buddy_static(raw[0:16])
                # Find the first null byte and truncate to ignore garbage/padding
                end = buddy_block.find(b'\x00')
                clean_block = buddy_block[:end] if end >= 0 else buddy_block
                s_buddy = clean_block.decode('utf-8', errors='ignore').strip()
                if _accept_only_if_in_game(s_buddy):
                    logger.info("0x1010 username resolved via Buddy static decrypt (0x5516b4 key): %s", user_id_req)
            except Exception:
                pass

        # 2) SHA1 digest match (FUN_004fa880): 32-byte payload -> digest; match SHA1(nick||token) or SHA1(uid||token).
        if (not user_id_req or not user_id_req.isprintable()) and len(raw) >= 32 and getattr(client, 'auth_token', None) and len(client.auth_token) >= 4:
            digest = GBCrypto.decrypt_1010_sha1_payload(raw[:32], KEY_GAME_STATIC_HEX)
            if digest is not None:
                for uid, nick in (client.server.db.get_all_game_user_identifiers() or []):
                    if GBCrypto.compute_client_sha1_username_token(nick, client.auth_token) == digest:
                        user_id_req = uid
                        logger.info("0x1010 username resolved via SHA1 digest match (NickName=%s)", nick)
                        break
                    if nick != uid and GBCrypto.compute_client_sha1_username_token(uid, client.auth_token) == digest:
                        user_id_req = uid
                        logger.info("0x1010 username resolved via SHA1 digest match (UserId=%s)", uid)
                        break

        # 3) Other keys/offsets: only accept if decrypted value is in game table.
        if not user_id_req or not user_id_req.isprintable():
            token_keys = []
            if getattr(client, 'auth_token', None) and len(client.auth_token) >= 4:
                t = client.auth_token
                token_keys = [
                    ((t + b'\x00' * 12)[:16], "auth_token zero-pad"),
                    ((t * 4)[:16], "auth_token 4x"),
                ]
            for offset in (0, 4, 8):
                if offset + 16 > len(raw):
                    continue
                block = raw[offset:offset + 16]
                for decrypt_fn in (GBCrypto.decrypt_game_static, GBCrypto.decrypt_broker_block):
                    try:
                        username_block = decrypt_fn(block)
                        s = username_block.decode('utf-8', errors='ignore').strip()
                        if _accept_only_if_in_game(s):
                            logger.debug("0x1010 username from offset %s with static key", offset)
                            break
                    except Exception:
                        pass
                if user_id_req and user_id_req.isprintable():
                    break
                for key_bytes, key_name in token_keys:
                    try:
                        username_block = GBCrypto.decrypt_with_key_bytes(block, key_bytes)
                        s = username_block.decode('utf-8', errors='ignore').strip()
                        if _accept_only_if_in_game(s):
                            logger.debug("0x1010 username decrypted with %s", key_name)
                            break
                    except Exception:
                        pass
                if user_id_req and user_id_req.isprintable():
                    break
        # 4) Full payload ECB decrypt (game/broker key); only accept if in game table.
        if (not user_id_req or not user_id_req.isprintable()) and raw and len(raw) >= 16:
            for key_hex in (KEY_GAME_STATIC_HEX, KEY_STATIC_HEX):
                try:
                    dec = GBCrypto.decrypt_blocks_ecb(raw, key_hex)
                    s = dec[:16].decode('utf-8', errors='ignore').strip()
                    if _accept_only_if_in_game(s):
                        break
                    dec_reader = PacketReader(dec)
                    candidate = dec_reader.read_string()
                    if candidate and _accept_only_if_in_game(candidate.strip()):
                        break
                except Exception:
                    pass
        # 5) Dynamic key (userId+password+authToken); already validates against known users.
        if (not user_id_req or not user_id_req.isprintable()) and raw and len(raw) >= 16 and getattr(client, 'auth_token', None):
            try:
                from .gunbound_dynamic_key import decrypt_first_block_with_dynamic_key
                known_uids = {uid for uid, _ in (client.server.db.get_users_with_passwords() or [])}
                for uid, pwd in (client.server.db.get_users_with_passwords() or []):
                    try:
                        dec = decrypt_first_block_with_dynamic_key(
                            raw[0:16], uid, pwd or "", client.auth_token
                        )
                        s = dec.decode('utf-8', errors='ignore').strip()
                        if s and len(s) < 32 and s in known_uids and client.server.db.get_user_game_data(s):
                            user_id_req = s
                            logger.info("0x1010 username resolved with dynamic key for user %s", s)
                            break
                        if s and s == uid and client.server.db.get_user_game_data(uid):
                            user_id_req = uid
                            logger.info("0x1010 username resolved with dynamic key for user %s", uid)
                            break
                    except Exception:
                        continue
            except Exception as e:
                logger.debug("Dynamic key try failed: %s", e)
    else:
        try:
            user_id_req = reader.read_string()
        except Exception:
            # Thor's Hammer / GBS: raw or null-terminated user_id
            if raw:
                end = raw.find(b'\x00')
                user_id_req = (raw[:end] if end >= 0 else raw).decode('utf-8', errors='ignore').strip()

    if not user_id_req or not user_id_req.strip():
        logger.error(
            "Error parsing login packet: could not read user_id. Payload len=%d hex=%s",
            len(reader.data),
            reader.data.hex().upper()[:80] if reader.data else b"",
        )
        return
        user_id_req = user_id_req.strip()
        # Reject decrypted garbage: only accept if this user exists in game table
        if not client.server.db.get_user_game_data(user_id_req):
            logger.warning(
                "Decrypted username %r not in Game table (UserId/NickName). Rejecting.",
                user_id_req,
            )
            return

    logger.info(f"Login request for user {user_id_req}")
    client.user_id = user_id_req

    game_data = client.server.db.get_user_game_data(client.user_id)
    if not game_data:
        logger.warning(
            "User %r not found in Game table (UserId/NickName). Rejecting login. Payload len=%d hex=%s",
            client.user_id, len(getattr(reader, 'data', b'') or b''),
            (getattr(reader, 'data', b'') or b'')[:80].hex().upper() if getattr(reader, 'data', None) else '',
        )
        raw = getattr(reader, 'data', b'')
        if raw and len(raw) >= 16:
            for key_name, key_hex in (('game', KEY_GAME_STATIC_HEX), ('broker', KEY_STATIC_HEX)):
                try:
                    dec = GBCrypto.decrypt_blocks_ecb(raw[:16], key_hex)
                    logger.debug(f"0x1010 first 16 bytes decrypted with {key_name}: hex={dec.hex()!r} utf8={dec.decode('utf-8', errors='replace')!r}")
                except Exception as e:
                    logger.debug(f"0x1010 decrypt {key_name}: {e}")
        return
    # Use canonical UserId from game table (handles lookup by NickName)
    client.user_id = game_data.get('UserId') or game_data.get('userid') or client.user_id

    # Mark session authenticated as early as possible after identity is resolved.
    # This avoids a timing window where the client is logged in but buddy actions
    # are still blocked because sender_client.is_authenticated is False.
    if (not client.is_authenticated) or (
        client.server.user_sessions.get(client.user_id.lower()) is not client
    ):
        client.is_authenticated = True
        client.server.register_user(client.user_id, client)

    ip_addr, port = client.ip
    client.server.db.login_log(client.user_id, ip_addr, port, '127.0.0.1', 8352, 0)

    buddies_raw = client.server.db.get_buddy_list(client.user_id)
    buddy_ids = [b['friend_id'] for b in buddies_raw]
    buddy_infos = client.server.db.get_users_info(buddy_ids)
    use_null_term = getattr(Config, 'BUDDY_LIST_NULL_TERMINATED', False)
    count_as_int = getattr(Config, 'BUDDY_LIST_COUNT_AS_INT', True)
    one_per_packet = getattr(Config, 'BUDDY_LIST_ONE_PER_PACKET', False)
    buddy_before_login = getattr(Config, 'BUDDY_LIST_BEFORE_LOGIN_RESP', False)
    # Official server: 0x1010 is answered by 0x1011 (Buddy List) then 0x3FFF (Sync).
    await send_friend_list(client)

    logger.info(f"Sent Buddy List (0x1011) and Sync (0x3FFF) for {client.user_id}")

    await client.server.status_manager.user_login(client.user_id)

    # Deliver persisted offline packets for the main 0x1000/0x1010 login flow.
    # Previously this was only done in handle_buddy_login().
    import asyncio
    await asyncio.sleep(1.0)
    await client.server.tunneling_manager.deliver_offline_tunnels(client)
    
    logger.info(f"User {client.user_id} logged in and received {len(buddy_infos)} buddies.")

async def handle_add_buddy(client, reader):
    if not client.is_authenticated or not client.user_id:
        logger.warning(f"[0x3010] Ignored unauthenticated add-buddy packet from {client.ip}")
        return

    # Packet 0x3010: Official server uses 16-byte null-padded nickname (capture Len=20).
    raw_payload = reader.data or b""
    friend_nick = ""
    if raw_payload:
        # Prefer first 16 bytes (null-padded), fallback to null-terminated
        chunk = raw_payload[:16].rstrip(b'\x00')
        if chunk:
            friend_nick = chunk.decode('utf-8', errors='ignore').strip()
        if not friend_nick:
            friend_nick = raw_payload.split(b'\x00')[0].decode('utf-8', errors='ignore').strip()
    
    if not friend_nick:
        logger.warning(f"Add Buddy failed: Could not parse friend name from 0x3010.")
        resp = PacketBuilder(SVC_ADD_BUDDY_RESP)
        resp.write_int(0)
        await client.send_packet(resp.build())
        return
        
    logger.info(f"Targeting friend req for: '{friend_nick}'")
    
    target_user_id = _resolve_canonical_user_id(client.server, friend_nick)
    if not target_user_id:
        friend_data = client.server.db.get_user_by_nickname(friend_nick)
        if friend_data:
            target_user_id = friend_data.get('UserId') or friend_data.get('Id')

    if not target_user_id:
        logger.warning("Add Buddy failed: Target user id not resolved.")
        resp = PacketBuilder(SVC_ADD_BUDDY_RESP)
        resp.write_int(0)
        await client.send_packet(resp.build())
        return

    if target_user_id.lower() == client.user_id.lower():
        logger.warning(f"Add Buddy blocked: self-add attempt by {client.user_id} using '{friend_nick}'")
        resp = PacketBuilder(SVC_ADD_BUDDY_RESP)
        resp.write_int(0)
        await client.send_packet(resp.build())
        return

    # Official server invitation Relay (0x2021)
    # Payload 41b: Nick(16) + UID(16) + Tag(9) = 45 total on wire
    sender_data = client.server.db.get_user_game_data(client.user_id) or {}
    sender_nick = sender_data.get('NickName') or client.user_id
    
    nick_bytes = sender_nick.encode('latin-1', errors='ignore')[:15].ljust(16, b'\x00')
    # Invite popup in some clients renders this 12-byte field as display name.
    # Use sender nickname here to avoid showing raw login id.
    uid_bytes = _enc_fixed(sender_nick, 12)
    
    # 16 Nick + 12 UID + 13 Tag = 41 (observed)
    tag = b'\x41\xC0\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20'
    buddy_req_payload_2021 = nick_bytes + uid_bytes + tag

    logger.info(f"Relaying Buddy Invitation: {client.user_id}({sender_nick}) -> {target_user_id}. Hex: {buddy_req_payload_2021.hex()}")

    await client.server.tunneling_manager.send_buddy_request_to_client(
        client, target_user_id, buddy_req_payload_2021, allow_offline_store=True
    )
    _mark_recent_buddy_request(client.server, client.user_id, target_user_id)
    
    # Success confirmation (4b)
    resp = PacketBuilder(SVC_ADD_BUDDY_RESP)
    resp.write_int(1)
    await client.send_packet(resp.build())

    # Sync (35b)
    sync = PacketBuilder(SVC_USER_SYNC)
    sync.write_short(0x0100)
    sync.write_bytes(sender_nick.encode('latin-1')[:15].ljust(16, b'\x00'))
    sync.write_bytes(binascii.unhexlify("0133bfabea000033bfabea0000"))
    await client.send_packet(sync.build())

async def handle_remove_buddy(client, reader):
    try:
        if not client.is_authenticated or not client.user_id:
            logger.warning(f"[0x3002] Ignored unauthenticated remove-buddy packet from {client.ip}")
            return

        # Official server: 0x3002 body = 16-byte null-padded friend id (capture Len=20: 4 header + 16 body)
        raw_payload = reader.data or b""
        friend_id = ""
        if raw_payload:
            chunk = raw_payload[:16].rstrip(b"\x00")
            if chunk:
                friend_id = chunk.decode("utf-8", errors="ignore").strip()
            if not friend_id:
                friend_id = raw_payload.split(b"\x00")[0].decode("utf-8", errors="ignore").strip()

        if not friend_id:
            logger.warning("Remove Buddy failed: could not parse friend id from 0x3002")
            resp = PacketBuilder(SVC_REMOVE_BUDDY_RESP)
            resp.write_int(0)
            await client.send_packet(resp.build())
            return

        # Normalize case/nickname variants and delete both relationship rows.
        friend_id = _resolve_canonical_user_id(client.server, friend_id) or friend_id
        # Some clients auto-send a mirrored 0x3002 after receiving the live remove popup.
        # If the pair was just removed, acknowledge and stop here to prevent ping-pong loops.
        if _was_recent_buddy_removal(client.server, client.user_id, friend_id, window_seconds=4.0):
            logger.info(f"[0x3002] Duplicate remove suppressed: {client.user_id} -> {friend_id}")
            resp = PacketBuilder(SVC_REMOVE_BUDDY_RESP)
            resp.write_int(1)
            resp.write_string(friend_id)
            await client.send_packet(resp.build())
            return

        removed_a = client.server.db.remove_buddy(client.user_id, friend_id)
        removed_b = client.server.db.remove_buddy(friend_id, client.user_id)
        success = bool(removed_a or removed_b)

        resp = PacketBuilder(SVC_REMOVE_BUDDY_RESP)
        if success:
            resp.write_int(1)
            resp.write_string(friend_id)
            logger.info(f"Mutual buddy removed: {client.user_id} <-> {friend_id}")
            _mark_recent_buddy_removal(client.server, client.user_id, friend_id)
        else:
            resp.write_int(0)

        await client.send_packet(resp.build())

        # Refresh buddy list instantly for both sides.
        await send_friend_list(client)
        target_session = _get_session_by_user_id(client.server, friend_id)
        if success and target_session:
            # Push explicit remove event so target client updates UI immediately.
            await _send_buddy_removed_popup(client.server, target_session, client.user_id)
            await send_friend_list(target_session)
    except Exception as e:
        logger.error(f"[0x3002] Error handling remove buddy: {e}")

async def handle_tunnel_packet(client, reader):
    """
    Handler para SVC_TUNNEL_PACKET (0x2020).
    Formatos observados no capture:
      - Buddy actions: payload comeÃ§a com flags/cÃ³digos e termina com 16 bytes de nickname null-padded
        (target_id). NÃ£o devemos depender apenas de UserNo.
    """
    try:
        if not client.is_authenticated or not client.user_id:
            logger.warning(f"[0x2020] Ignored unauthenticated tunnel packet from {client.ip}")
            return

        raw = reader.data or b""
        if len(raw) < 4:
            logger.warning("0x2020 payload too short")
            return

        # Primeiro, tenta resolver target_id pelo NICKNAME (Ãºltimos 16 bytes, null-padded)
        nickname_chunk = raw[-16:]
        target_id = nickname_chunk.rstrip(b"\x00").decode("latin-1", errors="ignore").strip()

        # Se ainda vazio, fallback para lÃ³gica antiga de UserNo
        if not target_id:
            raw_start = reader.offset
            try:
                target_id = reader.read_string()
            except Exception:
                target_id = ""

            if not target_id or (len(target_id) > 0 and ord(target_id[0]) < 32):
                reader.offset = raw_start
                try:
                    flag = reader.read_byte()
                    user_no = reader.read_int()
                except Exception:
                    user_no = None
                if user_no is not None:
                    user_data = client.server.db.get_user_game_data_by_id(user_no)
                    if user_data:
                        target_id = user_data.get("UserId") or user_data.get("NickName")
                        logger.info(f"0x2020 Target UserNo {user_no} resolved to {target_id}")
                    else:
                        logger.warning(f"0x2020 Target UserNo {user_no} not found in DB")

        if not target_id:
            logger.warning("Tunnel failed: Could not resolve target from 0x2020 payload")
            return

        # Normalize to canonical UserId (fixes case/nickname variants like Test2/test2).
        target_id = _resolve_canonical_user_id(client.server, target_id)
        if not target_id:
            logger.warning("Tunnel failed: target could not be canonicalized")
            return

        # payload_data = tudo exceto o nickname de 16 bytes no final
        payload_data = raw[:-16]

        # Status relay payload from client:
        # 0x2020 body = 00 + meta28 + 01 00 + target16
        # Relay as 0x2021 full: UID16 + Nick12 + meta28.
        if len(payload_data) == 31 and payload_data[0] == 0x00 and payload_data[29:31] == b'\x01\x00':
            meta = payload_data[1:29]
            _cache_meta_2021(client.server, client.user_id, meta)

            sender_data = client.server.db.get_user_game_data(client.user_id) or {}
            sender_nick = sender_data.get("NickName") or client.user_id
            relay_payload = _enc_fixed(client.user_id, 16) + _enc_fixed(sender_nick, 12) + meta

            ok = await client.server.tunneling_manager.send_buddy_request_to_client(
                client, target_id, relay_payload
            )
            if ok:
                logger.info(f"[0x2020] Status relay as 0x2021: {client.user_id} -> {target_id}")
            else:
                logger.warning(f"[0x2020] Status relay failed: {client.user_id} -> {target_id}")
            return

        # Chat via tunnel from client:
        # Observed pattern: 01 11 C0 <msg_len> 00 <msg...> 01 00 + target16
        # Relay/store as official 0x2021 chat:
        # UID16 + Nick12 + 11 C0 1F 00 + Msg40
        if len(payload_data) >= 7 and payload_data[:3] == b'\x01\x11\xC0' and payload_data[-2:] == b'\x01\x00':
            sender_data = client.server.db.get_user_game_data(client.user_id) or {}
            sender_nick = sender_data.get("NickName") or client.user_id

            msg_len = payload_data[3]
            msg_start = 5 if len(payload_data) > 4 and payload_data[4] == 0x00 else 4
            msg_end = len(payload_data) - 2
            if msg_start + msg_len <= msg_end:
                msg_raw = payload_data[msg_start:msg_start + msg_len]
            else:
                msg_raw = payload_data[msg_start:msg_end]

            msg_raw = msg_raw.split(b'\x00', 1)[0]
            msg_field = (msg_raw[:39] + b'\x00').ljust(40, b'\x00')

            chat_payload_2021 = (
                _enc_fixed(client.user_id, 16)
                + _enc_fixed(sender_nick, 12)
                + b'\x11\xC0\x1F\x00'
                + msg_field
            )

            ok = await client.server.tunneling_manager.send_buddy_request_to_client(
                client,
                target_id,
                chat_payload_2021,
                allow_offline_store=True,
            )
            if ok:
                logger.info(f"[0x2020] Chat relayed as 0x2021: {client.user_id} -> {target_id} (msg_len={len(msg_raw)})")
            else:
                logger.warning(f"[0x2020] Chat relay failed: {client.user_id} -> {target_id}")
            return

        # Buddy REQUEST via tunnel (0x01 0x41): client wants to add target.
        # Official server relays this as 0x2021 with 41-byte payload.
        if len(payload_data) >= 2 and payload_data[0] == 0x01 and payload_data[1] == 0x41:
            sender_nick = (client.server.db.get_user_game_data(client.user_id) or {}).get("NickName") or client.user_id
            nick_bytes = _enc_fixed(sender_nick, 16)
            # Keep invite display consistent with 0x3010 path (nickname-first UX).
            uid_bytes = _enc_fixed(sender_nick, 12)
            
            # Use confirmed 41-byte format for 0x2021 relay
            buddy_req_payload_2021 = nick_bytes + uid_bytes + b'\x41\xC0\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20'
            
            ok = await client.server.tunneling_manager.send_buddy_request_to_client(
                client, target_id, buddy_req_payload_2021, allow_offline_store=True
            )
            if ok:
                _mark_recent_buddy_request(client.server, client.user_id, target_id)
                logger.info(f"[0x2020] Buddy request (01 41) relayed as 0x2021: {client.user_id} -> {target_id}")
            return
        # Buddy decision parsing (critical):
        # Accept sample: 01 42 C0 01 00 01 ...
        # Reject sample: 01 42 C0 01 00 00 ...
        # Older variant may send 01 43 ... for reject.
        is_accept = False
        is_reject = False
        is_delete_action = False
        if len(payload_data) >= 6 and payload_data[:5] == b'\x01\x42\xC0\x01\x00':
            if payload_data[5] == 0x01:
                is_accept = True
            elif payload_data[5] == 0x00:
                is_reject = True
        elif len(payload_data) >= 2 and payload_data[0] == 0x01 and payload_data[1] == 0x43:
            # 0x43 is ambiguous in captures: can be invite-reject OR delete follow-up.
            if not _should_process_buddy_43(client.server, client.user_id, target_id):
                logger.debug(f"[0x2020] Throttled duplicate 0x43 action: {client.user_id} -> {target_id}")
                return
            if _was_recent_buddy_removal(client.server, client.user_id, target_id) or _users_are_buddies(client.server, client.user_id, target_id):
                is_delete_action = True
            else:
                is_reject = True
        elif len(payload_data) >= 1 and payload_data[0] == 0x42:
            # Legacy fallback (no decision flag available)
            is_accept = True

        if is_accept or is_reject:
            target_session = _get_session_by_user_id(client.server, target_id)
            if target_session:
                if is_accept:
                    if _should_emit_buddy_decision(client.server, client.user_id, target_id, True):
                        await _send_buddy_decision_popup(
                            client.server,
                            target_session,
                            client.user_id,
                            is_accept=True
                        )
                    else:
                        logger.debug(f"[DEDUP] Suppressed duplicate accept popup: {client.user_id} -> {target_id}")
                else:
                    if _should_emit_buddy_decision(client.server, client.user_id, target_id, False):
                        await _send_buddy_decision_popup(
                            client.server,
                            target_session,
                            client.user_id,
                            is_accept=False
                        )
                    else:
                        logger.debug(f"[DEDUP] Suppressed duplicate reject popup: {client.user_id} -> {target_id}")

        if is_accept:
            # Update DB FIRST
            client.server.db.add_buddy(client.user_id, target_id)
            client.server.db.add_buddy(target_id, client.user_id)
            logger.info(f"[0x2020] Mutual buddy added: {client.user_id} <-> {target_id}")

            # Notify and Refresh
            target_session = _get_session_by_user_id(client.server, target_id)
            my_game_data = client.server.db.get_user_game_data(client.user_id) or {}
            my_nick = my_game_data.get('NickName') or client.user_id
            
            if target_session:
                # Standard 60-byte Acceptance Notification
                nick_b = _enc_fixed(my_nick, 12)
                uid_b = _enc_fixed(client.user_id, 16)
                cached_meta = _get_cached_meta_2021(client.server, client.user_id)
                meta = cached_meta if cached_meta else _build_meta_2021(0x0012)
                
                out = PacketBuilder(SVC_RELAY_BUDDY_REQ)
                out.write_bytes(uid_b + nick_b + meta)
                await target_session.send_packet(out.build())
                
                await send_friend_list(target_session)
                await send_user_status_update(target_session, client.user_id, 0x0012)
            
            await send_friend_list(client)
            return
        if is_delete_action:
            # Suppress duplicate delete loops: some clients can emit repeated 0x01 0x43
            # after receiving delete/not-found updates.
            was_recent = _was_recent_buddy_removal(client.server, client.user_id, target_id, window_seconds=3.0)
            removed_a = client.server.db.remove_buddy(client.user_id, target_id)
            removed_b = client.server.db.remove_buddy(target_id, client.user_id)
            if removed_a or removed_b:
                logger.info(f"[0x2020] Mutual buddy removed: {client.user_id} <-> {target_id}")
                _mark_recent_buddy_removal(client.server, client.user_id, target_id)

                await send_friend_list(client)
                target_session = _get_session_by_user_id(client.server, target_id)
                if target_session:
                    await send_friend_list(target_session)
            else:
                if was_recent:
                    logger.debug(f"[0x2020] Duplicate delete suppressed: {client.user_id} -> {target_id}")
                    return
                logger.info(f"[0x2020] Delete action had no effect (already removed): {client.user_id} -> {target_id}")
                _mark_recent_buddy_removal(client.server, client.user_id, target_id)
            return
        if is_reject:
            logger.info(f"[0x2020] Buddy invite rejected: {client.user_id} -> {target_id}")
            return

        success = await client.server.tunneling_manager.tunnel_packet(
            client,
            target_id,
            0xA200,
            payload_data,
        )

        if not success:
            logger.warning(f"Tunnel failed: {client.user_id} -> {target_id}")

    except Exception as e:
        logger.error(f"Error handling tunnel packet: {e}")

async def handle_group_buddy(client, reader):
    friend_id = reader.read_string()
    group_name = reader.read_string()
    
    success = client.server.db.move_buddy_to_group(client.user_id, friend_id, group_name)
    
    if success:
        logger.info(f"Moved {friend_id} to group {group_name}")

async def handle_rename_group(client, reader):
    old_name = reader.read_string()
    new_name = reader.read_string()
    
    success = client.server.db.rename_group(client.user_id, old_name, new_name)
    if success:
        logger.info(f"Renamed group {old_name} to {new_name}")
    
    resp = PacketBuilder(SVC_RENAME_GROUP_RESP)
    resp.write_int(1 if success else 0)
    await client.send_packet(resp.build())

async def handle_user_state(client, reader):
    state = reader.read_int()
    client.state = state
    
async def handle_search(client, reader):
    search_nick = reader.read_string()
    
    user_data = client.server.db.get_user_by_search_term(search_nick)
    
    resp = PacketBuilder(SVC_SEARCH_RESP)
    if user_data:
        resp.write_int(1)
        resp.write_string(user_data['Id'])
        resp.write_string(user_data.get('NickName') or user_data.get('Nickname') or user_data.get('Id', ''))
    else:
        resp.write_int(0)
        
    await client.send_packet(resp.build())

# ============================================================================
# HANDLERS - INVITE SYSTEM
# ============================================================================

async def handle_send_invite(client, reader):
    """Handler para enviar convite."""
    from .invites import InviteType
    
    try:
        invite_type_value = reader.read_byte()
        target_id = reader.read_string()
        
        data = {}
        
        if invite_type_value == InviteType.GAME.value:
            data['room_name'] = reader.read_string()
            data['room_id'] = reader.read_int()
            data['server_ip'] = '127.0.0.1'
            data['server_port'] = 8400
        
        invite_type = InviteType(invite_type_value)
        
        invite_id = await client.server.invite_manager.send_invite(
            client,
            target_id,
            invite_type,
            data
        )
        
        logger.info(f"Invite sent: {client.user_id} -> {target_id} ({invite_type.name})")
        
    except Exception as e:
        logger.error(f"Error handling send invite: {e}")

async def handle_accept_invite(client, reader):
    """Handler para aceitar convite."""
    try:
        invite_id = reader.read_string()
        
        success = await client.server.invite_manager.accept_invite(client, invite_id)
        
        if success:
            logger.info(f"Invite accepted: {client.user_id} accepted {invite_id}")
        
    except Exception as e:
        logger.error(f"Error handling accept invite: {e}")

async def handle_reject_invite(client, reader):
    """Handler para rejeitar convite."""
    try:
        invite_id = reader.read_string()
        reason = ""
        try:
            reason = reader.read_string()
        except:
            pass
        
        success = await client.server.invite_manager.reject_invite(client, invite_id, reason)
        
        if success:
            logger.info(f"Invite rejected: {client.user_id} rejected {invite_id}")
        
    except Exception as e:
        logger.error(f"Error handling reject invite: {e}")

async def handle_cancel_invite(client, reader):
    """Handler para cancelar convite."""
    try:
        invite_id = reader.read_string()
        
        success = await client.server.invite_manager.cancel_invite(client, invite_id)
        
        if success:
            logger.info(f"Invite cancelled: {client.user_id} cancelled {invite_id}")
        
    except Exception as e:
        logger.error(f"Error handling cancel invite: {e}")

# ============================================================================
# HANDLERS - STATUS SYSTEM
# ============================================================================

async def handle_status_query(client, reader):
    """Handler para consulta de status."""
    try:
        target_id = reader.read_string()
        
        await client.server.status_manager.query_status(client, target_id)
        
    except Exception as e:
        logger.error(f"Error handling status query: {e}")

# ============================================================================
# HANDLERS - GAME INTEGRATION
# ============================================================================

async def handle_enter_game(client, reader):
    """Handler para quando usuÃ¡rio entra em jogo."""
    try:
        room_id = reader.read_int()
        room_name = reader.read_string()
        server_ip = reader.read_string()
        server_port = reader.read_int()
        
        game_data = {
            'room_id': room_id,
            'room_name': room_name,
            'server_ip': server_ip,
            'server_port': server_port
        }
        
        await client.server.status_manager.user_enter_game(client.user_id, game_data)
        
        logger.info(f"User {client.user_id} entered game: {room_name}")
        
    except Exception as e:
        logger.error(f"Error handling enter game: {e}")

async def handle_leave_game(client, reader):
    """Handler para quando usuÃ¡rio sai do jogo."""
    try:
        await client.server.status_manager.user_leave_game(client.user_id)
        
        logger.info(f"User {client.user_id} left game")
        
    except Exception as e:
        logger.error(f"Error handling leave game: {e}")

