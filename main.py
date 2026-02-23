"""
main module for the orchastrator server

"""

import json
from random import random
import asyncio
from time import sleep
from pydantic import ValidationError
import websockets
from websockets.asyncio.server import serve, broadcast
from argon2 import PasswordHasher

from dc import Login, MessageType, Privilege, Signal
from access import LoginFail, BanStop, authenticate


connected: set[websockets.ServerConnection] = set()
hasher = PasswordHasher()


async def on_connect(ws: websockets.ServerConnection) -> None:
    """
    ran on every connection to the server
    authenticates the user into the group thghey are entering and subscribes them to receive updates

    :param websocket: Description
    :type websocket: websockets.ServerConnection
    """
    version = await ws.recv()
    if version != "1":
        await ws.close(websockets.CloseCode.PROTOCOL_ERROR)
        return

    try:
        login = Login.model_validate_json(await ws.recv())  # validate data
        access = authenticate(login)  # authentication

    except TypeError, ValidationError:
        await ws.close(websockets.CloseCode.PROTOCOL_ERROR)
        return

    except LoginFail:
        sleep(4 * random())  # makes a login timing attack near impossible
        await ws.close(websockets.CloseCode.POLICY_VIOLATION)
        return

    if access.user.privilege == Privilege.ISOLATED:
        await ws.close(websockets.CloseCode.POLICY_VIOLATION)
        return

    connected.add(ws)
    await ws.send(map(lambda s: s.model_dump_json(), access.sync(login.last_sid)))

    listen = True

    if access.user.privilege == Privilege.SILENCED:
        listen = False
        await ws.wait_closed()

    while listen:
        message_to_relay: Signal | None = None
        try:
            message_received = Signal.model_validate_json(await ws.recv())
            match message_received.mtype:
                case MessageType.INTERNAL:
                    message_to_relay = access.save_signal(message_received)
                    broadcast(connected, message_received.model_dump_json())
                case MessageType.EXTERNAL:
                    content = json.loads(message_received.content)
                    match content["type"]:
                        case "user addition":
                            access.add_user(
                                content["username"],
                                content["privlage"],
                                content["password"],
                            )
            if message_to_relay:
                broadcast(connected, message_to_relay.model_dump_json())
        except ValueError, ValidationError:
            await ws.close(websockets.CloseCode.INVALID_DATA)
            break
        except BanStop as ban:
            await ws.close(websockets.CloseCode.POLICY_VIOLATION)
            broadcast(connected, ban.signal.model_dump_json())
            break
    connected.remove(ws)
    return


async def main() -> None:
    """
    entrypoint function of the orchastrator server
    """
    async with serve(on_connect) as server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
