"""
a CLI utility for configuring the instance as the user 'System'
"""
from genericpath import exists
import sqlite3
import random
from secrets import token_hex
from argon2 import PasswordHasher
from classes import User, Privlage, Signal, MessageType, systemUser




def main():
    """
    the main function of the instance configuration utility shpped with the server
    """
    action = input("Orchasrator serverside setup, what would you like to do?\n"
                    "n) create a new group\n"
                    "e) edit an existing group\n"
                    "r) delete a database\n > ")
    match action.casefold().strip():
        case "n":
            path = __file__
            while exists(path):
                gid = random.randbytes(8).hex()
                path = f"./db/{gid}.db"
            print("generated group ID " + gid) # type: ignore a gid will always be generated

            with sqlite3.connect(path) as db:

                db.executescript("""
                    CREATE TABLE users (uid INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, hash TEXT, salt TEXT, privlage INTEGER);
                    CREATE TABLE signals (sid INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, sender INTEGER, contents TEXT, type INTEGER);
                    CREATE TABLE objectives (oid INTEGER PRIMARY KEY AUTOINCREMENT, packagename TEXT, implementation BLOB)
                                 """
                    )
                db.commit()

                print("created tables, setting up users")

                db.execute("INSERT INTO users (username, hash, salt, privlage) VALUES (?, ?, ?, ?)",
                           tuple(systemUser.values()))
                # adding the system as a user

                salt = token_hex(16)
                admin: User = {
                "name": input("type a username, leave empty to finish\n > "),
                "salt": salt,
                "phash": PasswordHasher().hash(
                    password=input("type a password or passphrase\n > "),
                    salt=salt.encode()),
                "privlage": Privlage.ADMIN}

                db.execute("INSERT INTO users (username, hash, salt, privlage) VALUES (?, ?, ?, ?)",
                            tuple(admin.values()))
                db.commit()
                print("set up first admin " + admin["name"])
        case "e":
            gid = input("enter the id of the group you want to edit:\n")
        case "r":
            ...


if __name__ == "__main__":
    main()
