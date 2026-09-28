import asyncio
import logging
from typing import Optional
from ..core.pipeline import process_lines

logger = logging.getLogger("unilogx.syslog")

class SyslogProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        try:
            text = data.decode("utf-8", errors="replace").strip()
            if text:
                process_lines([text], source_file=f"udp_{addr[0]}_{addr[1]}")
        except Exception as exc:
            logger.error(f"Error processing syslog datagram: {exc}")

async def start_syslog_server(host: str = "127.0.0.1", port: int = 5140) -> Optional[asyncio.DatagramTransport]:
    loop = asyncio.get_running_loop()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(),
            local_addr=(host, port),
        )
        logger.info(f"Syslog UDP receiver listening on {host}:{port}")
        return transport
    except Exception as exc:
        logger.warning(f"Syslog UDP receiver could not bind to {host}:{port}: {exc}")
        return None
