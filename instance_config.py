"""
a CLI utility for configuring the instance as the user 'System'
"""

from pathlib import Path
import sqlite3
import random
from secrets import token_bytes
from argon2 import PasswordHasher


def main() -> None:
    """
    the main function of the instance configuration utility shpped with the server
    """
    action = input(
        "Orchasrator serverside setup, what would you like to do?\n"
        "n) create a new group\n"
        "r) delete a group\n > "
    )
    match action.casefold().strip():
        case "n":
            gid = random.randbytes(
                8
            ).hex()  # collision chance is 2^-64 which is tolerable
            path = f"./db/{gid}.db"
            print("generated group ID " + gid)

            with sqlite3.connect(path) as db:

                db.executescript(
                    """CREATE TABLE users
                                 (uid INTEGER PRIMARY KEY AUTOINCREMENT,
                                  username TEXT UNIQUE,
                                  privlage INTEGER,
                                  hash TEXT,
                                  salt TEXT);
                    CREATE TABLE signals 
                                 (sid INTEGER PRIMARY KEY AUTOINCREMENT,
                                  Timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                  sender INTEGER,
                                  contents TEXT,
                                  type INTEGER);
                    CREATE TABLE objectives 
                                 (oid INTEGER PRIMARY KEY AUTOINCREMENT,
                                  name TEXT,
                                  implementation TEXT)"""
                )

                print("created tables, setting up first admin")

                username = input("type a username\n > ")

                salt = token_bytes(16)
                phash = PasswordHasher().hash(
                    password=input("type a password or passphrase\n > "), salt=salt
                )
                db.execute(
                    "INSERT INTO users (username, hash, salt, privlage) VALUES (?, ?, ?, 0)",
                    (username, phash, salt),
                )

                print("set up first admin " + username)
        case "r":
            gid = input("enter the id of the group you want to delete:\n")
            try:
                Path(f"db/{gid}.db").unlink()
            except FileNotFoundError:
                print("id is wrong or group was already deleted")


if __name__ == "__main__":
    main()
