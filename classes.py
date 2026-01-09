"""
The file containing the data classes and enums for the data used by the server to handle data
"""
from dataclasses import dataclass
from enum import IntEnum
from typing import NotRequired, TypedDict


class Privlage(IntEnum):
    """
    an enum representing the level of privlage a user has
    the lower the level the greater the access
    every level can do anything the levels below it can

    :var ADMIN: the permission to change a groups features, editing automations and high permissions
    :vartype ADMIN: Literal[0]
    :var MODERATOR: the permission to add, remove and change lower permissions of users
    :vartype MODERATOR: Literal[1]
    :var PUBLISHER: the permission to send messages and transactions through different automations
    :vartype PUBLISHER: Literal[2]
    :var SILENCED: the permission to recive messages and transactions published
    :vartype SILENCED: Literal[3]
    """
    ADMIN = 0
    MODERATOR = 1
    PUBLISHER = 2
    SILENCED = 3


class MessageType(IntEnum):
    """
    type of a message
    external messages can only be sent by users with privlages moderator and up

    :var INTERNAL: message concerning an automation, encrypted between users
    :vartype INTERNAL: Literal[0]
    :var EXTERNAL: message concerning group config and user permissions, unecrypted
    :vartype EXTERNAL: Literal[1]
    """
    INTERNAL = 0
    EXTERNAL = 1


@dataclass
class User(TypedDict):
    """
    class holding data relating to a user
    inherits from TypedDict for seriallizabillity

    :var uid: user ID, assigned by the db and autoincremented as the addition order is public
    :vartype uid: NotRequired[int]
    :var name: username
    :vartype name: str
    :var phash: hash of the password
    :vartype phash: str
    :var salt: salt used in the password hashing proccess
    :vartype salt: str
    :var privlage: user's privlage level, see the enums docstring for more info
    :vartype privlage: Privlage
    """
    uid: NotRequired[int]
    name: str
    phash:str
    salt:str
    privlage:Privlage


@dataclass
class Signal(TypedDict):
    """
    a message or signal published by a user with adaquate permissions

    :var sid: signal ID, assigned by the db and autoincremented
    :vartype sender: NotRequired[int]
    :var timestamp: unix timestamp of the message, originally assigned by the db
    :vartype sender: NotRequired[int]
    :var sender: uid of the sender
    :vartype sender: int
    :var content: content of the message formatted json, encrypted in internal messages
    :vartype content: str
    :var mtype: type of message, external messages require special serverside handeling
    :vartype mtype: MessageType
    """
    sid: NotRequired[int]
    timestamp: NotRequired[int]
    sender: int
    content: str
    mtype: MessageType


systemUser: User = {"name": "System", "phash": "", "salt": "", "privlage":  Privlage.ADMIN}
