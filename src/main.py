"""
main module for the orchastrator server

"""

from http import HTTPStatus
import json
import logging
import random
import asyncio
import signal
import time
import pydantic
import websockets
import websockets.asyncio.server
import argon2

import dc
from access import DBAccess, BanStop, LoginFail


connected: dict[str, set[websockets.ServerConnection]] = {}
hasher = argon2.PasswordHasher()
logging.basicConfig(level=logging.DEBUG)


async def on_connect(ws: websockets.ServerConnection) -> None:
    """
    ran on every connection to the server
    authenticates the user into the group thghey are entering and subscribes them to receive updates

    :param websocket: Description
    :type websocket: websockets.ServerConnection
    """

    login = await greet(ws=ws)

    if not login:
        return

    dbaccess, peers = login

    last_sid = int(await ws.recv())

    for m in dbaccess.sync(last_sid):
        await ws.send(m.model_dump_json())

    listen = True

    if dbaccess.user.privilege == dc.Privilege.LISTENER:
        listen = False
        await ws.wait_closed()

    while listen:
        message_to_relay: dc.Signal | None = None
        try:
            message_received = dc.Signal.model_validate_json(await ws.recv())
            match message_received.mtype:
                case dc.MessageType.INTERNAL:
                    message_to_relay = dbaccess.save_signal(message_received)
                    websockets.asyncio.server.broadcast(
                        peers, message_received.model_dump_json()
                    )
                case dc.MessageType.EXTERNAL:
                    content = json.loads(message_received.content)
                    match content["type"]:
                        case "user addition":
                            message_to_relay = dbaccess.add_user(
                                content["username"],
                                content["privilege"],
                                content["password"],
                            )
                        case "perm":
                            message_to_relay = dbaccess.set_permission(
                                uid=content["uid"], privilege=content["new"]
                            )
            if message_to_relay:
                websockets.asyncio.server.broadcast(
                    peers, message_to_relay.model_dump_json()
                )
        except ValueError, pydantic.ValidationError:
            await ws.close(websockets.CloseCode.INVALID_DATA)
            break
        except websockets.ConnectionClosedOK:
            logging.info("a conncetion has closed normally")
            break
        except websockets.ConnectionClosedError:
            logging.info("a connection has closed abnormally")
            break
        except BanStop as ban:
            await ws.close(websockets.CloseCode.POLICY_VIOLATION)
            websockets.asyncio.server.broadcast(peers, ban.signal.model_dump_json())
            break
    peers.remove(ws)
    return


async def greet(
    ws: websockets.ServerConnection,
) -> tuple[DBAccess, set[websockets.ServerConnection]] | None:
    """
    function that handles authenticating new users

    :param ws: connection to operate over
    :type ws: websockets.ServerConnection
    :return: a tuple with a DBAccess instance and the set of all users in the group
    :rtype: tuple[DBAccess, set[websockets.ServerConnection]] | None
    """

    if not ws.request:
        await ws.close(websockets.CloseCode.MANDATORY_EXTENSION)
        logging.info("received empty request")
        return
    logging.info("started a connection to %s", ws.request.path)
    try:
        hello = await ws.recv()
        login = dc.Login.model_validate_json(hello)  # validate data

    except websockets.ConnectionClosed as err:
        logging.info("connection rapidly closed for %s", err.reason)
        return

    except pydantic.ValidationError as err:
        logging.debug("validation error from %s", err.errors())
        await ws.close(websockets.CloseCode.PROTOCOL_ERROR)
        return

    gid = ws.request.path.removeprefix("/")

    try:
        dbaccess = DBAccess(gid=gid)
        dbaccess.authenticate(login)  # authentication

    except LoginFail as fail:
        time.sleep(
            4 * random.random()
        )  # throttles and makes a login timing attack near impossible
        logging.info("login fail for reason: %s", fail.args[0])
        await ws.close(websockets.CloseCode.POLICY_VIOLATION)
        return

    connected.setdefault(gid, set()).add(ws)

    return (dbaccess, connected[gid])


def ensure_path(
    connection: websockets.ServerConnection, request: websockets.Request
) -> websockets.Response | None:
    """
    checks the request has a group id as path,
    may be replaced with something more comprehensive in the future
    """
    if request.path == "/":
        return connection.respond(HTTPStatus.BAD_REQUEST, "group path required\n")
    logging.info("rejected a pathless connection")


async def main() -> None:
    """
    entrypoint function of the orchastrator server
    """
    logging.info("starting up...")
    async with websockets.asyncio.server.serve(
        on_connect, port=443, process_request=ensure_path
    ) as server:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, server.close)
        await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
