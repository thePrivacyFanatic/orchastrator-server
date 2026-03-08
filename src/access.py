"""module containing the dbaccess class which inherits from a sqlite connction"""

import logging
import sqlite3
from secrets import token_hex
from os.path import isfile
from typing import Any, NoReturn
from argon2 import PasswordHasher
import dc


class LoginFail(Exception):
    """
    an exception indicating an incorrect login, should always be caught
    has a reason string as the first arg
    (nonexistent group/user, wrong credentials and insufficient permission)
    """

    reason: str

    def __init__(self, reason: str, *args: object) -> None:
        super().__init__(*args)
        self.reason = reason


class BanStop(Exception):
    """
    an exception thrown after isolating a user to broadcast the ban

    :var signal: signal advertizing the ban
    :vartype signal: Signal
    """

    signal: dc.Signal
    reason: str

    def __init__(self, signal: dc.Signal, reason: str, *args: object) -> None:
        super().__init__(*args)
        self.signal = signal
        self.reason = reason


class DBAccess:
    """
    an access manager handeling authentication when constructed and authorization for all commands

    :var gid: gid of group to use
    :vartype gid: str
    """

    user: dc.User
    _db: sqlite3.Connection

    def __init__(self, gid: str) -> None:
        path = f"./db/{gid}.db"
        if isfile(path):
            self._db = sqlite3.connect(path)
        else:
            raise LoginFail(f"nonexistent group: {gid}")

    def authenticate(
        self, login: dc.Login, hasher: PasswordHasher = PasswordHasher()
    ) -> None:
        """
        authenticates a user from a login, sets it as the dbaccesses user

        :param login: login info for user
        :type login: Login
        :param hasher: optional hasher override
        :type hasher: PasswordHasher
        """
        entry: tuple[int, str, int, str, str]
        if not (
            entry := self._db.execute(
                "SELECT uid, username, privilege, hash, salt FROM users WHERE username=?",
                (login.username,),
            ).fetchone()
        ):
            raise LoginFail(f"nonexistent user {login.username}")
        # validated user existence
        if hasher.hash(login.password, salt=entry[4].encode()) != entry[3]:
            raise LoginFail(f"wrong password for {login.username}")
        # authenticated user
        if dc.Privilege(entry[2]) == dc.Privilege.BANNED:
            raise LoginFail(f"user is banned {login.username}")
        self.user = dc.User(
            uid=entry[0], name=login.username, privilege=dc.Privilege(entry[2])
        )

    def _save(self, table_name: str, values: dict[str, Any]) -> tuple:
        """
        a function for adding rows to the database asyncronously and returning the added row

        :param table_name: name of the table to save into
        :type table_name: str
        :param values: dictionary of the columns and the values to save in it,
        id and timestamp are managed by the db
        :type values: dict[str, Any]
        :return: tuple of the added row
        :rtype: tuple[Any, ...]
        """
        with self._db:
            query = (
                "INSERT INTO "
                + table_name
                + " "
                + str(tuple(values.keys()))
                + " VALUES "
                + str(tuple(values.values()))
            )
            # print(query)
            self._db.execute(query)

            return self._db.execute(
                f"""SELECT * FROM {table_name} ORDER BY rowid DESC LIMIT 1"""
            ).fetchone()

    def save_signal(self, message: dc.Signal) -> dc.Signal:
        """
        add a message to the db and return it with an id and a timesstamp
        handels access control as well

        :param message: the signal recived
        :type message: Signal
        :return: the signal, now with a non-null id and timestamp
        :rtype: Signal
        """
        if message.sid or message.timestamp or message.sender:
            self.isolate("preconstructed message")
        if self.user.privilege < dc.Privilege.PUBLISHER:
            self.isolate("insufficient permissions to publish")

        return dc.Signal.from_tuple(
            self._save(
                "signals",
                {
                    "sender": self.user.uid,
                    "contents": message.content,
                    "type": int(message.mtype),
                },
            )
        )

    def add_user(
        self,
        username: str,
        privilege: dc.Privilege,
        password: str,
        hasher: PasswordHasher = PasswordHasher(),
    ) -> dc.Signal:
        """
        add a user to the db and return a notification signal

        :param username: name of the new user
        :type username: str
        :param privilege: initial privilege level of the new user
        :type privilege: privilege
        :param password: password of the new user
        :type password: str
        :param hasher: optional custom hash settings for the password
        :type hasher: PasswordHasher
        :return: a user object of the new user
        :rtype: User
        """
        if self.user.privilege < max(privilege, dc.Privilege.MODERATOR):
            self.isolate("instfficient privileges for user addition")
        salt = token_hex(16)
        phash = hasher.hash(password=password, salt=salt.encode())

        user = dc.User.from_tuple(
            self._save(
                "users",
                {
                    "username": username,
                    "privilege": int(privilege),
                    "hash": phash,
                    "salt": salt,
                },
            )[:3]
        )

        return self.save_signal(
            dc.Signal(
                content=f'{{"type": "user addition", '
                f'"user": {user.model_dump_json()}}}',
                mtype=dc.MessageType.EXTERNAL,
            )
        )

    def add_objective(self, obj: dc.Objective) -> dc.Signal:
        """
        currently dead code, waiting for flutter_eval to work to use for modularity
        add an objective to the db and return a notifying signal

        :param obj: the objective to add
        :type obj: Objective
        :return: signal notifying users about the objective
        :rtype: Signal
        """
        if self.user.privilege < dc.Privilege.ADMIN:
            self.isolate("insufficient privilege for objective addition")
        obj = dc.Objective.from_tuple(
            self._save("objectives", {"implementation": obj.implementation})
        )
        return self.save_signal(
            dc.Signal(
                content=f'{{"type" : "objective addition", '
                f'"objective": {obj.model_dump_json()}}}',
                mtype=dc.MessageType.EXTERNAL,
            )
        )

    def hide_objective(self, oid: int) -> dc.Signal:
        """
        remove an objective if possessing permissions and return a notifying signal
        this will not remove the objective's data

        :param oid: oid of removed objective
        :type oid: int
        :return: signal notifying users that the objective has been removed
        :rtype: Signal
        """
        if self.user.privilege != dc.Privilege.ADMIN:
            self.isolate("insufficient privilege for objective addition")
        self._db.execute("DELETE FROM objectives WHERE id=?", (oid,))
        return self.save_signal(
            dc.Signal(
                content=f'{{"type": "objective hiding", ' f'"oid": {oid}}}',
                mtype=dc.MessageType.EXTERNAL,
            )
        )

    def isolate(self, reason: str) -> NoReturn:
        """
        demotes the current user to isolated
        then throws a BanStop to immediatly halt all connection with said user
        and allow the server to broadcast an isolation notice
        """
        uid = self.user.uid
        self.user = dc.systemUser
        sig = self._modify_perms(uid, dc.Privilege.BANNED)
        raise BanStop(signal=sig, reason=reason)

    def _modify_perms(self, uid: int, privilege: dc.Privilege) -> dc.Signal:
        """
        private method to modify a user's permission
        should be encapsulated by methods enforcing authorization

        :param uid: user id of user getting promoted or demoted
        :type uid: int
        :param privilege: new privilege to be set
        :type privilege: Privilege
        :return: signal to notify users of the change
        :rtype: Signal
        """
        with self._db:
            self._db.execute(
                "UPDATE users SET privilege = ? WHERE uid=?;", (privilege, uid)
            )
        return self.save_signal(
            dc.Signal(
                content=f'{{"type" : "perm", "uid" : {uid}, "new": {privilege}}}',
                mtype=dc.MessageType.EXTERNAL,
            )
        )

    def set_permission(self, uid: int, privilege: dc.Privilege) -> dc.Signal:
        """
        function that allowes increasing permissions of a user
        bans users with insufficient permissions (less than mod or mod promoting above publisher)

        :param uid: uid of user getting promoted
        :type uid: int
        :param privilege: new privilege to be granted if allowed
        :type privilege: privilege
        :return: signal to notify users of the promotion
        :rtype: Signal
        """
        og_priv = dc.Privilege(
            self._db.execute(
                "SELECT privilege FROM users WHERE uid=?", (uid,)
            ).fetchone()[0]
        )
        logging.debug(
            "started perm change by %s to change a %s to %s",
            self.user.privilege,
            og_priv,
            privilege,
        )
        if (
            self.user.privilege < dc.Privilege.MODERATOR  # insufficient permission
            or (
                self.user.privilege == dc.Privilege.MODERATOR
                and privilege > dc.Privilege.PUBLISHER  # mod privilege escelation
            )
            or self.user.privilege < og_priv  # userping attempt
        ):

            self.isolate("disallowed permission change")
        else:
            return self._modify_perms(uid, privilege)

    def sync(self, last_sid: int) -> tuple[dc.Signal, ...]:
        """
        returns all signals sent after a specified one

        :param last_sid: sid of the last signal recived
        :type last_sid: int
        :return: tuple of all signals with a higher sid
        :rtype: tuple
        """
        return tuple(
            map(
                dc.Signal.from_tuple,
                self._db.execute(
                    "SELECT sid, timestamp, sender, contents, type FROM signals WHERE sid>?",
                    (last_sid,),
                ).fetchall(),
            )
        )

    def introduce(self) -> dc.Introduction:
        """
        dumps all current user and objective data to two lists in a tuple
        currently only kept for compatibillity reasons
        """
        return dc.Introduction(
            users=tuple(
                map(
                    lambda u: dc.User.from_tuple(u[:3]),
                    self._db.execute("SELECT * FROM users").fetchall(),
                )
            ),
            objectives=tuple(
                map(
                    dc.Objective.from_tuple,
                    self._db.execute("SELECT * FROM objectives").fetchall(),
                )
            ),
        )

    def change_password(
        self, new_password: str, hasher: PasswordHasher = PasswordHasher()
    ) -> None:
        """
        change own user password

        :param new_password: new password for user to use
        :type new_password: str
        :param hasher: optional hasher for alternate hash settings
        :type hasher: PasswordHasher
        """
        salt = (
            self._db.execute("SELECT salt FROM users WHERE uid=?", (self.user.uid,))
            .fetchone()
            .encode()
        )
        new_hash = hasher.hash(new_password, salt=salt)
        self._db.execute(
            "UPDATE users SET hash=? WHERE uid=?", (new_hash, self.user.uid)
        )
