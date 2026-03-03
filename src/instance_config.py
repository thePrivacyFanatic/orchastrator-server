"""
a CLI utility for configuring the instance as the user 'System'
"""

import pathlib
import sqlite3
import random

import access
import dc


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
            print("generated group ID " + gid)

            with sqlite3.connect(f"./db/{gid}.db") as db:

                db.executescript(
                    """CREATE TABLE users
                                 (uid INTEGER PRIMARY KEY AUTOINCREMENT,
                                  username TEXT UNIQUE,
                                  privilege INTEGER,
                                  hash TEXT,
                                  salt TEXT);
                    CREATE TABLE signals 
                                 (sid INTEGER PRIMARY KEY AUTOINCREMENT,
                                  Timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                  sender INTEGER,
                                  contents TEXT,
                                  type INTEGER);"""
                )

                print("created tables, accessing")

                dba = access.DBAccess(gid=gid)

                dba.user = dc.systemUser

                username = input("type a username\n > ")
                password = input("type a password or passphrase\n > ")

                dba.add_user(
                    username=username, privilege=dc.Privilege.ADMIN, password=password
                )

                print("set up first admin " + username)
        case "r":
            gid = input("enter the id of the group you want to delete:\n")
            try:
                pathlib.Path(f"db/{gid}.db").unlink()
            except FileNotFoundError:
                print("id is wrong or group was already deleted")


if __name__ == "__main__":
    main()
