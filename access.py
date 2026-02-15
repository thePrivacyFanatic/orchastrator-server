"""module containing the dbaccess class which inherits from a sqlite connction"""
import sqlite3
from secrets import token_bytes
from os.path import isfile
from typing import Any, NoReturn
from argon2 import PasswordHasher
from dc import Introduction, MessageType, Objective, Privlage, User, Signal, Login


class LoginFail(Exception):
    """
    an exception indicating an incorrect login, should always be handled
    """


class BanStop(Exception):
    """
    an exception thrown after isolating a user to broadcast the ban

    :var signal: signal advertizing the ban
    :vartype signal: Signal
    """
    signal: Signal
    def __init__(self, signal:Signal, *args: object) -> None:
        super().__init__(*args)
        self.signal = signal


class DBAccess():
    """
    an access manager handeling authentication when constructed and authorization for all commands

    :var user: user object of connected user
    :vartype user: User
    :var db: database connection to use
    :vartype db: Connection
    """
    user: User
    _db: sqlite3.Connection
    def __init__(self, user: User, db: sqlite3.Connection) -> None:
        self.user = user
        self._db = db

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
            self._db.execute("INSERT INTO " + table_name +
                             str(tuple(values.keys())) +
                             " VALUES " + str(tuple(values.values())))
            return self._db.execute(f"""SELECT *
                                    FROM {table_name}
                                    ORDER BY rowid DESC LIMIT 1""").fetchone()
        
    def _remove(self, table: str, id: int) -> None:
        """
        remove row with id from a table

        :param table: title of table to remove from
        :type table: str
        :param id: id of entry to delete
        :type id: int
        """
        with self._db:
            self._db.execute("DELETE FROM ? ")
        

    def save_signal(self, message: Signal) -> Signal:
        """
        add a message to the db and return it with an id and a timesstamp
        handels access control as well
        
        :param message: the signal recived
        :type message: Signal
        :return: the signal, now with a non-null id and timestamp
        :rtype: Signal
        """
        if message.id or message.timestamp or message.sender:
            self.isolate()
        return Signal.from_tuple(self._save("signals",
                                  {"sender": self.user.id,
                                   "contents": message.content,
                                   "type": int(message.mtype)}))

    def add_user(self,
                 username: str,
                 privlage:Privlage,
                 password: str,
                 hasher: PasswordHasher = PasswordHasher()) -> User:
        """
        add a user to the db and return it with a uid

        :param username: name of the new user
        :type username: str
        :param privlage: initial privlage level of the new user
        :type privlage: Privlage
        :param password: password of the new user
        :type password: str
        :param hasher: optional custom hash settings for the password
        :type hasher: PasswordHasher
        :return: a user object of the new user
        :rtype: User
        """
        if self.user.privlage > min(privlage, Privlage.MODERATOR):
            self.isolate()
        salt = token_bytes(16)
        phash = hasher.hash(password=password, salt=salt)
        return User.from_tuple(self._save("users",
                                {"username": username,
                                 "privlage": int(privlage),
                                 "hash": phash,
                                 "salt": salt})[:3])

    def add_objective(self, obj: Objective) -> Objective:
        """
        add an objective to the db and return it with an oid

        :param obj: the objective to add
        :type obj: Objective
        """
        if self.user.privlage > Privlage.ADMIN:
            self.isolate()
        return Objective.from_tuple(self._save("objectives",
                                     {"name": obj.name,
                                      "implementation": obj.implementation}))

    def isolate(self) -> NoReturn:
        """
        demotes the current user to isolated
        then throws a BanStop to immediatly halt all connection with said user
        and allow the server to broadcast an isolation notice
        """
        sig = self._modify_perms(self.user.id, Privlage(4))
        raise BanStop(sig)

    def _modify_perms(self, uid: int, privlage: Privlage) -> Signal:
        """
        private method to modify a user's permission
        should be encapsulated by methods enforcing authorization
        
        :param uid: user id of user getting promoted or demoted
        :type uid: int
        :param privlage: new privlage to be set
        :type privlage: Privlage
        :return: signal to notify users of the change
        :rtype: Signal
        """
        with self._db:
            self._db.execute("UPDATE users SET privlage = ? WHERE uid=?;", (privlage, uid))
        return self.save_signal(Signal(sender=self.user.id,
                                content=f'{{"type" : "perm", "uid" : {uid}}}',
                                mtype=MessageType.EXTERNAL))

    def set_permission(self, uid: int, privlage: Privlage) -> Signal:
        """
        function that allowes increasing permissions of a user
        bans users with insufficient permissions (less than mod or mod promoting above publisher)
        
        :param uid: uid of user getting promoted
        :type uid: int
        :param privlage: new privlage to be granted if allowed
        :type privlage: Privlage
        :return: signal to notify users of the promotion
        :rtype: Signal
        """
        og_priv = self._db.execute("SELECT privlage FROM users WHERE uid=?", (uid,)).fetchone()
        if (self.user.privlage > Privlage.MODERATOR
            # insufficient permission
            or
        (self.user.privlage == Privlage.MODERATOR and privlage < Privlage.PUBLISHER)
        # mod privlage escelation
        or
        self.user.privlage > og_priv):
            # userping attempt
            self.isolate()
        else:
            return self._modify_perms(uid, privlage)


    def sync(self, last_sid: int) -> tuple[Signal, ...]:
        """
        returns all signals sent after a specified one
        
        :param last_sid: sid of the last signal recived
        :type last_sid: int
        :return: tuple of all signals with a higher sid
        :rtype: tuple
        """
        return tuple(map(lambda s :Signal(*s),
                   self._db.execute("SELECT * FROM signals WHERE sid>?", (last_sid,)).fetchall()))

    def introduce(self) -> Introduction:
        """
        dumps all current user and objective data to two lists in a tuple
        """
        return Introduction(
            users = tuple(map(lambda u: User.from_tuple(u[:3]),
                              self._db.execute("SELECT * FROM users").fetchall())),
            objectives=tuple(map(Objective.from_tuple,
                                 self._db.execute("SELECT * FROM objectives").fetchall())))




def authenticate(login: Login, hasher: PasswordHasher = PasswordHasher()) -> DBAccess:
    """
    takes a login object and an optional alternate hasher and creates a dbaccess instance

    :param login: obect with instance id username and password
    :type login: Login
    :param hasher: alternate hash settings
    :type hasher: PasswordHasher
    :return: instance for the user to access said instance
    :rtype: DBAccess
    """
    path = f"db/{login.gid}.db"
    if not isfile(path):
        raise LoginFail
    # validating group existence
    db = sqlite3.connect(path)
    if not (entry := db.execute(
    "SELECT uid, username, hash, salt, privlage FROM users WHERE username=?",
      (login.username,)).fetchone()):
        raise LoginFail
    # validating user existence
    if hasher.hash(login.password, salt=entry[3]) != entry.hash:
        raise LoginFail
    # authenticated user
    user = User(id=entry.uid, name=login.username, privlage=Privlage(entry.privlage))
    return DBAccess(user, db)
