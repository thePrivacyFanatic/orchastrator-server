"""module containing the dbaccess class which inherits from a sqlite connction"""
import sqlite3
from os.path import isfile
from typing import Iterable, NoReturn
from argon2 import PasswordHasher
from dc import MessageType, Privlage, User, Signal, Login


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
    Docstring for DBAccess
    """
    def __init__(self, login: Login, hasher: PasswordHasher = PasswordHasher()) -> None:
        path = f"db/{login.gid}.db"
        if not isfile(path):
            raise LoginFail
        # validating group existence
        self.db = sqlite3.connect(path)
        if not (entry := self.db.execute(
        "SELECT uid, username, hash, salt, privlage FROM users WHERE username=?",
          (login.username,)).fetchone()):
            raise LoginFail
        # validating user existence
        if hasher.hash(login.password, salt=entry.salt.encode()) != entry.hash:
            raise LoginFail
        # authenticated user
        self.user = User(uid=entry.uid, name=login.username, privlage=Privlage(entry.privlage))

    def save(self, message: Signal) -> Signal:
        """
        save a message in the db and return it with its assigned id and timesstamp
        
        :param message: the signal recived
        :type message: Signal
        :return: the signal, now with a non-null id and timestamp
        :rtype: Signal
        """
        with self.db:  # aqcuire lock
            self.db.execute("""INSERT INTO signals (timestamp, sender, contents, privlage)
                        VALUES (unixepoch(), ?, ?, 0)""", (self.user.uid, message.content))
            self.db.commit()
            sig = Signal(*self.db.execute("""SELECT (sid, timestamp, sender, contents, type)
                           FROM signals ORDER BY sid DESC LIMIT 1""").fetchone())
        return sig

    def isolate(self) -> NoReturn:
        """
        demotes the current user to banned
        """
        with self.db:
            self.db.execute("UPDATE users SET privlage = 4 WHERE uid=?;", (self.user.uid,))
            sig = self.save(Signal(None, None, 0, f"""{{"type" : "perm", "uid" : {self.user.uid}, "new", 5}}""", MessageType.EXTERNAL))
            self.db.commit()
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
        with self.db:
            self.db.execute("UPDATE users SET privlage = ? WHERE uid=?;", (privlage, uid))
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
        privlage > self.db.execute("SELECT privlage FROM users WHERE uid=?", (uid,)).fetchone()):
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
                   *self.db.execute("SELECT * FROM signals WHERE sid>?", (last_sid,)).fetchall())
