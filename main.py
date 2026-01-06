import asyncio
import sqlite3
import websockets
from websockets.asyncio.server import serve
import json
from os.path import isfile
from argon2 import PasswordHasher, exceptions


connected = set()
hasher = PasswordHasher()


async def handler(websocket: websockets.ServerConnection) -> None:
    login = json.loads(await websocket.recv())
    path = f"db/{login["instance"]}.db"
    if (not isfile(path)):
        return await websocket.close(3000)
        
    with sqlite3.connect(path) as db:
        try:
            phash: str
            salt: str
            phash, salt = db.execute("SELECT hash,salt FROM  users WHERE username=?", (login["username"],)).fetchone()
            PasswordHasher.verify(hasher, phash, login["password"] + salt)
        except exceptions.VerifyMismatchError:
            return await websocket.close(3000)
            
        


async def main() -> None:
    async with serve(handler) as server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
