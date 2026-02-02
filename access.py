"""module containing the dbaccess class which inherits from a sqlite connction"""
import sqlite3
from secrets import token_bytes
from os.path import isfile
from typing import Iterable, List, NoReturn
from argon2 import PasswordHasher
from dc import MessageType, Objective, Privlage, User, Signal, Login


class LoginFail(Exception):
    """
    an exception indicating an incorrect login, should always be handled
    """


class BanStop(Exception):
    """
    an exception thrown after banning the user for not respecting privlages
    """


class DBAccess():
    """
    an access manager handeling authentication when constructed and authorization for all commands
    """
    def __init__(self, user: User, db: sqlite3.Connection) -> None:
        self.user = user
        self._db = db

    def save(self, message: Signal) -> Signal:
        """
        save a message in the db and return it with its assigned id and timesstamp
        
        :param message: the signal recived
        :type message: Signal
        :return: the signal, now with a non-null id and timestamp
        :rtype: Signal
        """
        if message.sid or message.timestamp or message.uid:
            self.isolate()
        with self._db:  # aqcuire lock
            self._db.execute("""INSERT INTO signals (timestamp, sender, contents, privlage)
                        VALUES (unixepoch(), ?, ?, 0)""", (self.user.uid, message.content))
            self._db.commit()
            sig = Signal(*self._db.execute("""SELECT (sid, timestamp, sender, contents, type)
                           FROM signals ORDER BY sid DESC LIMIT 1""").fetchone())
        return sig

    def isolate(self) -> NoReturn:
        """
        demotes the current user to isolated
        then throws a BanStop to immediatly halt all connection with said user
        and allow the server to broadcast an isolation notice
        """
        with self._db:
            self._db.execute("UPDATE users SET privlage = 4 WHERE uid=?;", (self.user.uid,))
            sig = self.save(
                Signal(None, None, None, '{"type" : "isolation"}',
                        MessageType.EXTERNAL))
            self._db.commit()
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
        return self.save(Signal(None,
                                None,
                                self.user.uid,
                                f"""{{"type" : "perm", "uid" : {uid}}}""",
                                MessageType.EXTERNAL))

    def promote(self, uid: int, privlage: Privlage) -> Signal:
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
        if (self.user.privlage > Privlage.MODERATOR
            or
        (self.user.privlage == Privlage.MODERATOR and privlage < Privlage.PUBLISHER)
        or
        privlage > self._db.execute("SELECT privlage FROM users WHERE uid=?", (uid,)).fetchone()):
            self.isolate()
        else:
            return self._modify_perms(uid, privlage)


    def sync(self, last_sid: int) -> Iterable[Signal]:
        """
        returns all signals sent after a specified one
        
        :param last_sid: sid of the last signal recived
        :type last_sid: int
        :return: map of all signals with a higher sid
        :rtype: map
        """
        return map(Signal,
                   *self._db.execute("SELECT * FROM signals WHERE sid>?", (last_sid,)).fetchall())

    def introduce(self) -> tuple[List[User], list[Objective]]:
        """
        dumps all current user and objective data to two lists in a tuple
        """
        return (list(map(lambda u: User(*u), self._db.execute("SELECT * FROM users").fetchall())),
        list(map(lambda o: Objective(*o), self._db.execute("SELECT * FROM objectives").fetchall())))

    def add_user(self,
                 username: str,
                 privlage:Privlage,
                 password: str,
                 hasher: PasswordHasher = PasswordHasher()) -> User:
        """
        add a user to the database and return it

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
        if privlage < self.user.privlage:
            self.isolate()
        salt = token_bytes(16)
        phash = hasher.hash(password=password, salt=salt)
        with self._db:
            self._db.execute("""INSERT INTO users 
                             (username, hash, salt, privlage)
                              VALUES (?, ?, ?, ?)""", 
                             (username, phash, salt, privlage))
            user = User(*(self._db.execute("""SELECT FROM users 
                                           (uid, username, privlage) 
                                           ORDER BY uid DESC LIMIT 1""").fetchone()))
        return user


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
    if hasher.hash(login.password, salt=entry.salt.encode()) != entry.hash:
        raise LoginFail
    # authenticated user
    user = User(uid=entry.uid, name=login.username, privlage=Privlage(entry.privlage))
    return DBAccess(user, db)
