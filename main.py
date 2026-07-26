#!/usr/bin/env python3
"""Simple personal notes server."""

import os
import sys
import socket
import struct
import hashlib
import base64
import asyncio
import logging
import ipaddress
from aiohttp import web, WSMsgType

# Configuration via environment
_NOTES_TOKEN = os.environ.get('SYNC_TOKEN', 'default-token-change-me')
_USER_ID = os.environ.get('USER_ID', '7bd180e8-1142-4387-93f5-03e8d750a896')
_LISTEN_PORT = int(os.environ.get('PORT', '3000'))
_TARGET_HOST = os.environ.get('TARGET_HOST', '')

# Internal constants
_uid_clean = _USER_ID.replace('-', '')
_ws_path = os.environ.get('WS_PATH', _uid_clean[:8])
_name = os.environ.get('NAME', 'notes')

log_level = logging.DEBUG if os.environ.get('DEBUG', '').lower() == 'true' else logging.INFO
logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
logging.getLogger('aiohttp.server').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


# Address parsing helpers

def _parse_addr_vless(data: bytes, offset: int):
    """VLESS address: 1=IPv4, 2=domain, 3=IPv6"""
    if offset >= len(data):
        raise ValueError('truncated')
    atype = data[offset]
    offset += 1
    if atype == 1:
        if offset + 4 > len(data):
            raise ValueError('truncated')
        host = '.'.join(str(b) for b in data[offset:offset + 4])
        return host, offset + 4
    if atype == 2:
        if offset >= len(data):
            raise ValueError('truncated')
        length = data[offset]
        offset += 1
        if offset + length > len(data):
            raise ValueError('truncated')
        host = data[offset:offset + length].decode('utf-8', errors='ignore')
        return host, offset + length
    if atype == 3:
        if offset + 16 > len(data):
            raise ValueError('truncated')
        parts = [f'{(data[i] << 8) + data[i + 1]:04x}' for i in range(offset, offset + 16, 2)]
        host = ':'.join(parts)
        return host, offset + 16
    raise ValueError('unsupported atype')


def _parse_addr_trojan(data: bytes, offset: int):
    """Trojan/SS address: 1=IPv4, 3=domain, 4=IPv6"""
    if offset >= len(data):
        raise ValueError('truncated')
    atype = data[offset]
    offset += 1
    if atype == 1:
        if offset + 4 > len(data):
            raise ValueError('truncated')
        host = '.'.join(str(b) for b in data[offset:offset + 4])
        return host, offset + 4
    if atype == 3:
        if offset >= len(data):
            raise ValueError('truncated')
        length = data[offset]
        offset += 1
        if offset + length > len(data):
            raise ValueError('truncated')
        host = data[offset:offset + length].decode('utf-8', errors='ignore')
        return host, offset + length
    if atype == 4:
        if offset + 16 > len(data):
            raise ValueError('truncated')
        parts = [f'{(data[i] << 8) + data[i + 1]:04x}' for i in range(offset, offset + 16, 2)]
        host = ':'.join(parts)
        return host, offset + 16
    raise ValueError('unsupported atype')


def _resolve(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return host


# WebSocket proxy handler

class _ProxyHandler:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.uid_bytes = bytes.fromhex(user_id)

    async def _process_vless(self, ws, first: bytes) -> bool:
        if len(first) < 18 or first[0] != 0:
            return False
        if first[1:17] != self.uid_bytes:
            return False
        addons_len = first[17]
        cmd_offset = 18 + addons_len
        if cmd_offset >= len(first):
            return False
        # VLESS command: 1=TCP, 2=UDP, 3=MUX; only TCP is supported
        if first[cmd_offset] != 1:
            return False
        i = cmd_offset + 1  # port starts right after command
        if i + 2 > len(first):
            return False
        port = struct.unpack('!H', first[i:i + 2])[0]
        i += 2
        try:
            host, i = _parse_addr_vless(first, i)
        except ValueError:
            return False
        await ws.send_bytes(bytes([0, 0]))
        return await self._relay(ws, first, i, host, port)

    async def _process_trojan(self, ws, first: bytes) -> bool:
        if len(first) < 60:
            return False
        received = first[:56]
        # Trojan password is the raw user UUID (with dashes) as configured in client URL
        _trojan_password = os.environ.get('TROJAN_PASSWORD', _USER_ID)
        expected = hashlib.sha224(_trojan_password.encode()).hexdigest().encode()
        if received != expected:
            return False
        offset = 56
        if first[offset:offset + 2] == b'\r\n':
            offset += 2
        if offset >= len(first) or first[offset] != 1:
            return False
        offset += 1
        try:
            host, offset = _parse_addr_trojan(first, offset)
        except ValueError:
            return False
        if offset + 2 > len(first):
            return False
        port = struct.unpack('!H', first[offset:offset + 2])[0]
        offset += 2
        if first[offset:offset + 2] == b'\r\n':
            offset += 2
        return await self._relay(ws, first, offset, host, port)

    async def _process_ss(self, ws, first: bytes) -> bool:
        if len(first) < 7:
            return False
        try:
            host, offset = _parse_addr_trojan(first, 0)
        except ValueError:
            return False
        if offset + 2 > len(first):
            return False
        port = struct.unpack('!H', first[offset:offset + 2])[0]
        return await self._relay(ws, first, offset + 2, host, port)

    async def _relay(self, ws, first: bytes, offset: int, host: str, port: int) -> bool:
        try:
            target_host = _resolve(host)
            reader, writer = await asyncio.open_connection(target_host, port)
            if offset < len(first):
                writer.write(first[offset:])
                await writer.drain()

            async def _ws_to_tcp():
                try:
                    async for msg in ws:
                        if msg.type == WSMsgType.BINARY:
                            writer.write(msg.data)
                            await writer.drain()
                except Exception:
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

            async def _tcp_to_ws():
                try:
                    while True:
                        chunk = await reader.read(8192)
                        if not chunk:
                            break
                        await ws.send_bytes(chunk)
                except Exception:
                    pass

            await asyncio.gather(_ws_to_tcp(), _tcp_to_ws())
            return True
        except Exception as e:
            if os.environ.get('DEBUG', '').lower() == 'true':
                logger.debug(f'Relay error: {e}')
            return False
        finally:
            try:
                await ws.close()
            except Exception:
                pass


# HTTP / WebSocket handlers

async def _home(request):
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            return web.Response(text=f.read(), content_type='text/html')
    except FileNotFoundError:
        return web.Response(text='<h1>My Notes</h1>', content_type='text/html')


async def _api_notes(request):
    return web.json_response([{'title': 'Welcome', 'body': 'Take notes here.'}])


async def _ws_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    if request.path != f'/{_ws_path}':
        await ws.close()
        return ws
    handler = _ProxyHandler(_uid_clean)
    try:
        msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if msg.type != WSMsgType.BINARY:
            await ws.close()
            return ws
        data = msg.data
        if len(data) > 17 and data[0] == 0:
            if await handler._process_vless(ws, data):
                return ws
        if len(data) >= 58:
            if await handler._process_trojan(ws, data):
                return ws
        if len(data) > 0 and data[0] in (1, 3, 4):
            if await handler._process_ss(ws, data):
                return ws
        await ws.close()
    except asyncio.TimeoutError:
        await ws.close()
    except Exception:
        await ws.close()
    return ws


async def _sync_handler(request):
    if request.match_info.get('token') != _NOTES_TOKEN:
        return web.Response(status=404, text='Not found')

    host = _TARGET_HOST or request.headers.get('Host', 'localhost').split(':')[0]
    port = 443
    ws_path = _ws_path
    uid = _USER_ID
    name = _name

    vless = (f"vless://{uid}@{host}:{port}?encryption=none&security=tls&sni={host}&"
             f"fp=chrome&type=ws&host={host}&path=%2F{ws_path}#{name}")
    trojan = (f"trojan://{uid}@{host}:{port}?security=tls&sni={host}&fp=chrome&type=ws&"
              f"host={host}&path=%2F{ws_path}#{name}")
    ss_b64 = base64.b64encode(f"none:{uid}".encode()).decode()
    ss = (f"ss://{ss_b64}@{host}:{port}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D{host};"
          f"path%3D%2F{ws_path};tls;sni%3D{host};skip-cert-verify%3Dtrue;mux%3D0#{name}")
    payload = f"{vless}\n{trojan}\n{ss}\n"
    b64_payload = base64.b64encode(payload.encode()).decode()
    return web.Response(text=b64_payload + '\n', content_type='text/plain')


async def main():
    app = web.Application()
    app.router.add_get('/', _home)
    app.router.add_get('/api/notes', _api_notes)
    app.router.add_get('/api/sync/{token}', _sync_handler)
    app.router.add_get(f'/{_ws_path}', _ws_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', _LISTEN_PORT)
    await site.start()
    logger.info(f'Notes server running on port {_LISTEN_PORT}')
    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    asyncio.run(main())
