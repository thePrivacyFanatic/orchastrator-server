"""
main module for the orchastrator server

"""
from random import random
import asyncio
from time import sleep
from pydantic import ValidationError
import websockets
from websockets.asyncio.server import serve, broadcast
from argon2 import PasswordHasher

from dc import Login, MessageType, Signal
from access import LoginFail, BanStop, authenticate


connected: set[websockets.ServerConnection] = set()
hasher = PasswordHasher()


async def on_connect(ws: websockets.ServerConnection) -> None:
    """
    ran on every connection to the server
    authenticates the user into the group thghey are entering and subscribes them to recive updates
    
    :param websocket: Description
    :type websocket: websockets.ServerConnection
    """
    version = await ws.recv()
    if version != "1":
        await ws.close(websockets.CloseCode.PROTOCOL_ERROR)
        return
    try:
        login = Login.model_validate_json(await ws.recv())  # validate data
        man = authenticate(login)  # authentication
    except TypeError, ValidationError:
        await ws.close(websockets.CloseCode.PROTOCOL_ERROR)
        return
    except LoginFail:
        sleep(4 * random())  # makes a login timing attack near impossible
        await ws.close(websockets.CloseCode.POLICY_VIOLATION)
        return
    connected.add(ws)
    await ws.send(map(lambda s: s.model_dump_json(), man.sync(login.last_sid)))
    while True:
        try:
            message = Signal.model_validate_json(await ws.recv())
            match message.mtype:
                case  MessageType.INTERNAL:
                    man.save_signal(message)
                    broadcast(connected, message.model_dump_json())
                case MessageType.EXTERNAL:
                    ...
        except ValueError, ValidationError:
            await ws.close(websockets.CloseCode.INVALID_DATA)
            return
        except BanStop as ban:
            await ws.close()
            broadcast(
                connected,
                ban.signal.model_dump_json())
            return


async def main() -> None:
    """
    entrypoint function of the orchastrator server
    """
    async with serve(on_connect) as server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
