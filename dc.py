"""
The file containing the data classes and enums for the data used by the server to handle data
"""
from enum import IntEnum
from sqlite3.dbapi2 import Timestamp
from typing import ClassVar, Optional, Protocol, TypeVar
from pydantic.dataclasses import dataclass



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
    :var ISOLATED: temporary permission level of users that overreach their
    :vartype ISOLATED: Literal[4]
    """
    ADMIN = 0
    MODERATOR = 1
    PUBLISHER = 2
    SILENCED = 3
    ISOLATED = 4


class MessageType(IntEnum):
    """
    type of a message
    external messages can only be sent by users with privlages moderator and up

    :var INTERNAL: message concerning an automation, encrypted between users
    :vartype INTERNAL: Literal[0]
    :var EXTERNAL: message concerning user permissions, unecrypted, requires high permissions
    :vartype EXTERNAL: Literal[1]
    """
    INTERNAL = 0
    EXTERNAL = 1


@dataclass
class User:
    """
    class holding data relating to a user

    :var uid: user ID, assigned by the db and autoincremented as the addition order is public
    :vartype uid: int
    :var name: username
    :vartype name: str
    :var privlage: user's privlage level, see the enums docstring for more info
    :vartype privlage: Privlage
    """
    uid: int
    name: str
    privlage:Privlage

    def __post_init__(self) -> None:
        self.privlage = Privlage(self.privlage)


@dataclass
class Signal:
    """
    a message or signal published by a user with adaquate permissions

    :var sid: signal ID, assigned by the db and autoincremented
    :vartype sid: Optional[int]
    :var timestamp: unix timestamp of the message, originally assigned by the db
    :vartype timestamp: Optional[int]
    :var uid: uid of the sender
    :vartype uid: Optional[int]
    :var content: content of the message formatted json, encrypted in internal messages
    :vartype content: str
    :var mtype: type of message, external and executive messages require serverside handeling
    :vartype mtype: MessageType
    """
    sid: Optional[int] = None
    timestamp: Optional[Timestamp] = None
    uid: Optional[int] = None
    content: str = ""
    mtype: MessageType = MessageType.INTERNAL

    def __post_init__(self) -> None:
        self.mtype = MessageType(self.mtype)

@dataclass
class Login:
    """
    the initial data object sent by the client when connecting

    :var gid: the gid of the group they are connecting to
    :vartype gid: int
    :var username: the user's username
    :vartype username: str
    :var password: the user's password
    :vartype password: str
    """
    gid: int
    username: str
    password: str
    last_sid: int


@dataclass
class Objective:
    """
    an objective widget that can send and receive data when on the client

    :var oid: id of the objective
    :vartype oid: int
    :var name: name for admin access, client has its own handling
    :vartype name: int
    :var implementation: dart bytecode file of objective widget
    :vartype implementation: Blob
    """
    oid: Optional[int]
    name: str
    implementation: str


class _DataClassProtocol(Protocol):
    __dataclass_fields__: ClassVar[dict]



DataClass = TypeVar("DataClass", bound=_DataClassProtocol)
