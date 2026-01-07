import asyncio
import sqlite3
import websockets
from websockets.asyncio.server import serve, broadcast
import json
from os.path import isfile
from argon2 import PasswordHasher, exceptions


connected: set[websockets.ServerConnection] = set()
hasher = PasswordHasher()


async def on_connect(websocket: websockets.ServerConnection) -> None:
    login = json.loads(await websocket.recv())
    path = f"db/{login["instance"]}.db"
    if (not isfile(path)): return await websocket.close(3000)
    with sqlite3.connect(path) as db:
        known_hash: str
        salt: str
        known_hash, salt = db.execute("SELECT hash,salt FROM users WHERE username=?", (login["username"],)).fetchone()
        if (PasswordHasher.hash(hasher, login["password"], salt=salt.encode()) != known_hash) : return await websocket.close(3000)
        
        
            
            
        


async def main() -> None:
    async with serve(on_connect) as server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
