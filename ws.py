import ssl
import asyncio
import websockets
from datetime import datetime

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
#openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"

log_filename = datetime.now().strftime("ws_%Y%m%d-%H%M%S.log")
log_file = open(log_filename, "a", buffering=1)

def log(msg):
    print(msg)
    log_file.write(msg + "\n")

async def handle_client(websocket: websockets.WebSocketServerProtocol):
    client_ip = websocket.remote_address[0]
    log(f"Client connected from {client_ip}")

    try:
        async for message in websocket:
            log(message)
    except websockets.ConnectionClosed:
        log("Client disconnected")

async def main():
    log(f"Logging to {log_filename}")
    async with websockets.serve(handle_client, "0.0.0.0", 1337, ssl=ssl_context):
        log("listening to 0.0.0.0:1337...")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())