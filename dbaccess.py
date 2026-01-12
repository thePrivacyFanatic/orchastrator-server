"""module containing the dbaccess class which inherits from a sqlite connction"""
import sqlite3
from os.path import isfile
from argon2 import PasswordHasher
from classes import Privlage, User, Signal, Login


class LoginFail(Exception):
    """
    an exception indicating an incorrect login, should always be handled
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
        
        :param self: the db access manager
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

    def _ban(self, uid:int):
        with self.db:
            self.db.execute("UPDATE users SET privlage = 3 WHERE uid=?;", (uid,))
            self.db.execute("""INSERT INTO signals
                            (timestamp, sender, contents, type) 
                            VALUES (unixepoch(), 0, 'DEMOTED {?}', 0)""",(uid,))
            self.db.commit()
