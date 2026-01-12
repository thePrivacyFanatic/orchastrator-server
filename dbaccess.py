"""module containing the dbaccess class which inherits from a sqlite connction"""
import sqlite3
from os.path import isfile
from argon2 import PasswordHasher
from classes import Privlage, MessageType, User, Signal, Login, UserEntry


class LoginFail(Exception):
    """
    an exception indicating an incorrect login
    """


class DBAccess():
    """
    Docstring for DBAccess
    """
    def __init__(self, login: Login, hasher: PasswordHasher = PasswordHasher()) -> None:
        path = f"db/{login['gid']}.db"
        if not isfile(path):
            raise LoginFail
        # validating group existence
        self.db = sqlite3.connect(path)
        if not (entry := UserEntry(*self.db.execute(
        "SELECT uid, username, hash, salt, privlage FROM users WHERE username=?",
          (login["username"],)).fetchone())):
            raise LoginFail
        # validating user existence
        if hasher.hash(login["password"], salt=entry.salt.encode()) != entry.hash:
            raise LoginFail
        # authenticated user
        self.user = User(uid=entry[0], name=login["username"], privlage=Privlage(entry.privlage))
