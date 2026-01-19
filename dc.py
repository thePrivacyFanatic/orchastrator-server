"""
The file containing the data classes and enums for the data used by the server to handle data
"""
from dataclasses import asdict, dataclass
from enum import IntEnum
import json
from typing import Optional



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

    :var EXECUTIVE: message concerning group configuration, unencrypted, modifies objectives table
    :vartype EXECUTIVE: Literal[0]
    :var EXTERNAL: message concerning user permissions, unecrypted, modifies the users table
    :vartype EXTERNAL: Literal[1]
    :var INTERNAL: message concerning an automation, encrypted between users
    :vartype INTERNAL: Literal[2]
    """
    INTERNAL = 2
    EXTERNAL = 1
    EXECUTIVE = 0


@dataclass
class User:
    """
    class holding data relating to a user
    inherits from TypedDict for seriallizabillity

    :var uid: user ID, assigned by the db and autoincremented as the addition order is public
    :vartype uid: NotRequired[int]
    :var name: username
    :vartype name: str
    :var privlage: user's privlage level, see the enums docstring for more info
    :vartype privlage: Privlage
    """
    uid: int
    name: str
    privlage:Privlage


@dataclass
class Signal:
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
    :var mtype: type of message, external and executive messages require serverside handeling
    :vartype mtype: MessageType
    """
    sid: Optional[int]
    timestamp: Optional[int]
    sender: int
    content: str
    mtype: MessageType

    def asjson(self) -> str:
        """
        convert signal to json
        
        :param self: the signal being converted
        :return: json string of signal
        :rtype: str
        """
        return json.dumps(asdict(self))

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


systemUser = User(0, "System", Privlage.ADMIN)
