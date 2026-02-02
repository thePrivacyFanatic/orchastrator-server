"""
a CLI utility for configuring the instance as the user 'System'
"""
import sqlite3
import random
from secrets import token_hex
from argon2 import PasswordHasher


def main() -> None:
    """
    the main function of the instance configuration utility shpped with the server
    """
    action = input("Orchasrator serverside setup, what would you like to do?\n"
                    "n) create a new group\n"
                    "e) edit an existing group\n"
                    "r) delete a database\n > ")
    match action.casefold().strip():
        case "n":
            gid = random.randbytes(8).hex()  # collision chance is 2^-64 which is tolerable
            path = f"./db/{gid}.db"
            print("generated group ID " + gid)

            with sqlite3.connect(path) as db:

                db.executescript("""
                    CREATE TABLE users (uid INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, hash TEXT, salt TEXT, privlage INTEGER);
                    CREATE TABLE signals (sid INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, sender INTEGER, contents TEXT, type INTEGER);
                    CREATE TABLE objectives (oid INTEGER PRIMARY KEY AUTOINCREMENT, displayName TEXT, implementation BLOB)
                                 """
                    )

                print("created tables, setting up users")

                username = input("type a username, leave empty to finish\n > ")

                salt = token_hex(16)
                phash = PasswordHasher().hash(
                    password=input("type a password or passphrase\n > "),
                    salt=salt.encode())
                db.execute("INSERT INTO users (username, hash, salt, privlage) VALUES (?, ?, ?, 0)",
                           (username, phash, salt))

                print("set up first admin " + username)
                db.execute("""INSERT INTO signals 
                           (timestamp, sender, contents, type) 
                           VALUES (unixepoch(), 0, "INITIALLIZED", 0)""")
                print("marked start")

        case "e":
            gid = input("enter the id of the group you want to edit:\n")
        case "r":
            ...


if __name__ == "__main__":
    main()
