"""
main module for the orchastrator server

"""
from random import random
import asyncio
import json
from time import sleep
import websockets
from websockets.asyncio.server import serve, broadcast
from argon2 import PasswordHasher

from dc import Login, MessageType, Signal
from dbaccess import DBAccess, LoginFail, BanStop


connected: set[websockets.ServerConnection] = set()
hasher = PasswordHasher()


async def on_connect(ws: websockets.ServerConnection) -> None:
    """
    ran on every connection to the server
    authenticates the user into the group thghey are entering and subscribes them to recive updates
    
    :param websocket: Description
    :type websocket: websockets.ServerConnection
    """
    try:
        login = Login(*json.loads(await ws.recv()).values())  # validate data
        man = DBAccess(login)  # authentication
    except TypeError:
        await ws.close(websockets.CloseCode.PROTOCOL_ERROR)
        return
    except LoginFail:
        sleep(4 * random())  # makes a timing attack near impossible
        await ws.close(websockets.CloseCode.POLICY_VIOLATION)
        return
    connected.add(ws)
    await ws.send(map(lambda s: s.asjson(), man.sync(login.last_sid)))
    while True:
        try:
            message = Signal(None, None, man.user.uid, *json.loads(await ws.recv()).values())
            match message.mtype:
                case  MessageType.INTERNAL:
                    man.save(message)
                    broadcast(connected, message.asjson())
                case MessageType.EXTERNAL:
                    ...
                case MessageType.EXECUTIVE:
                    ...
        except ValueError:
            await ws.close(websockets.CloseCode.INVALID_DATA)
            return
        except BanStop as ban:
            await ws.close()
            broadcast(
                connected,
                ban.args[0].asjson())
            return


async def main() -> None:
    """
    entrypoint function of the orchastrator server
    """
    async with serve(on_connect) as server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
