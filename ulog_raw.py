import socket
from datetime import datetime

def ts():
    return datetime.now().strftime('%H:%M:%S.%f')[:-3]

# Define host and port
HOST = '0.0.0.0'
PORT = 8089

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"Listening on {HOST}:{PORT}...")

    try:
        while True:  # Outer loop keeps the server running
            conn, addr = s.accept()
            print(f"\n[{ts()}] [NEW CONNECTION] Connected by {addr}")

            with conn:
                while True:  # Inner loop handles data from the current client
                    data = conn.recv(1024)
                    if not data:
                        print(f"[{ts()}] [DISCONNECTED] Client {addr} disconnected.")
                        break  # Breaks inner loop, returns to s.accept()

                    print(f"{data.decode('utf-8').strip()}")

    except KeyboardInterrupt:
        print("\n[SHUTTING DOWN] Server stopped by user.")
