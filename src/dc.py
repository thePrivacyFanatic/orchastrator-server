"""
The file containing the data classes and enums for the data used by the server to handle data
"""

from enum import IntEnum
from sqlite3.dbapi2 import Timestamp
from typing import Optional, Self
from pydantic import BaseModel


class _entryModel(BaseModel):
    @classmethod
    def from_tuple(cls, tpl: tuple) -> Self:
        """
        instantiates the model from a tuple like in a dataclass

        :param tpl: tuple of values to add must be the same as in the call decleration
        :return: the model
        :rtype: Self
        """
        return cls(**dict(zip(cls.model_fields.keys(), tpl)))


class Privilege(IntEnum):
    """
    an enum representing the level of privlage a user has
    the lower the level the greater the access
    every level can do anything the levels below it can

    :var ADMIN: the permission to change a groups features, editing automations and high permissions
    :vartype ADMIN: Literal[4]
    :var MODERATOR: the permission to add, remove and change lower permissions of users
    :vartype MODERATOR: Literal[3]
    :var PUBLISHER: the permission to send messages and transactions through different automations
    :vartype PUBLISHER: Literal[2]
    :var LISTENER: the permission to recive messages and transactions published
    :vartype LISTENER: Literal[1]
    :var BANNED: permission level for banned users
    :vartype BANNED: Literal[0]
    """

    ADMIN = 4
    MODERATOR = 3
    PUBLISHER = 2
    LISTENER = 1
    BANNED = 0


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


class User(_entryModel):
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
    privilege: Privilege


class Signal(_entryModel):
    """
    a message or signal published by a user with adaquate permissions

    :var id: signal ID, assigned by the db and autoincremented
    :vartype id: Optional[int]
    :var timestamp: unix timestamp of the message, originally assigned by the db
    :vartype timestamp: Optional[int]
    :var uid: sender of the sender
    :vartype sender: Optional[int]
    :var content: content of the message formatted json, encrypted in internal messages
    :vartype content: str
    :var mtype: type of message, external and executive messages require serverside handeling
    :vartype mtype: MessageType
    """

    sid: Optional[int] = None
    timestamp: Optional[Timestamp] = None
    sender: Optional[int] = None
    content: str = ""
    mtype: MessageType = MessageType.INTERNAL


class Objective(_entryModel):
    """
    an objective widget that can send and receive data when on the client

    :var id: id of the objective
    :vartype id: int
    :var name: name for admin access, client has its own handling
    :vartype name: int
    :var implementation: dart bytecode file of objective widget
    :vartype implementation: Blob
    """

    oid: Optional[int]
    implementation: str


class Login(_entryModel):
    """
    the initial data object sent by the client when connecting

    :var gid: the gid of the group they are connecting to
    :vartype gid: int
    :var username: the user's username
    :vartype username: str
    :var password: the user's password
    :vartype password: str
    """

    username: str
    password: str


class Introduction(BaseModel):
    """
    model used for sending the initial group state
    only uses a model for ease of seriallization

    :var users: users currently in the group
    :var objectives: objectives currently used in the group
    """

    users: tuple[User, ...]
    objectives: tuple[Objective, ...]


systemUser = User(uid=0, name="SYSTEM", privilege=Privilege.ADMIN)
