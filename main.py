"""
main module for the orchastrator server

"""
import asyncio
import sqlite3
import json
from os.path import isfile
import websockets
from websockets.asyncio.server import serve, broadcast
from argon2 import PasswordHasher


connected: set[websockets.ServerConnection] = set()
hasher = PasswordHasher()


async def on_connect(websocket: websockets.ServerConnection) -> None:
    """
    ran on every connection to the server
    authenticates the user into the group thghey are entering and subscribes them to recive updates
    
    :param websocket: Description
    :type websocket: websockets.ServerConnection
    """
    login = json.loads(await websocket.recv())
    path = f"db/{login["group"]}.db"
    if not isfile(path):
        await websocket.close(3000)
        return
    # confirmed the instance exists
    db = sqlite3.connect(path)
    uid:int
    phash: str
    salt: str
    privlage: int
    uid,phash,salt,privlage = db.execute(
        "SELECT uid, hash, salt, privlage FROM users WHERE username=?", (login["username"],)
        ).fetchone()
    if PasswordHasher.hash(hasher, login["password"], salt=salt.encode()) != phash:
        await websocket.close(3000)
        db.close()
        return
    # authenticated as a user
    connected.add(websocket)
    await websocket.send(
        map(json.dumps,
             db.execute("SELECT * FROM signals WHERE sid>?", (login["last_signal"],)).fetchall()))
    while privlage < 3:  # listen loop
        try:
            message = json.loads(await websocket.recv())
            if message["executive"] == 1:
                if privlage > 1:
                    with db:
                        db.execute("UPDATE users SET privlage=2 WHERE uid=?", (uid,))
                        db.execute("""INSERT INTO signals (timestamp, sender, contents, privlage)
                                    VALUES (unixepoch(), 0, ?, 0)""",
                                    (json.dumps({"type": "ban", "uid": uid}),))
        except websockets.ConnectionClosed:
            connected.remove(websocket)
            break
        with db:
            db.execute("""INSERT INTO signals (timestamp, sender, contents, privlage)
                        VALUES (unixepoch(), ?, ?, 0)""", (uid, message))
            db.commit()
            row = dict(zip(
                db.execute("""SELECT (sid, timestamp, sender, contents) 
                           FROM signals ORDER BY sid DESC LIMIT 1""").fetchone(),
                ("sid", "timestamp", "sender", "content")))
        broadcast(connections=connected, message=json.dumps(row))

async def main() -> None:
    """
    entrypoint function of the orchastrator server
    """
    async with serve(on_connect) as server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
