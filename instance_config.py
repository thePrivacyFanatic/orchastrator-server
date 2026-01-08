import sqlite3
import random
from secrets import token_hex
from argon2 import PasswordHasher


def main():
    """
    the main function of the instance configuration utility shpped with the server
    """
    action = input("Orchasrator serverside setup, what would you like to do?\n"
                    "n) create a new group\n"
                    "e) edit an existing group\n"
                    "r) delete a database")
    match action.casefold().strip():
        case "n":
            gid = random.randbytes(8).hex()
            print("generated group ID " + gid)
            with sqlite3.connect(f"./db/{gid}.db") as db:
                db.executescript("""
                    CREATE TABLE users ( uid INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, hash TEXT, salt TEXT, privlage INTEGER );
                    CREATE TABLE signals ( sid INTEGER PRIMARY KEY `AUTOINCREMENT, timestamp INTEGER, sender INTEGER, contents TEXT, type INTEGER ); """
                    )
                db.commit()
                print("created tables, adding first admin")
                hasher = PasswordHasher()
                name = input("type a username, leave empty to finish\n > ")
                password = input("type a password or passphrase\n > ")
                salt = token_hex(16)
                phash = PasswordHasher.hash(hasher, password=password, salt=salt.encode())
                db.execute("INSERT INTO users (username, hash, salt, privlage) VALUES (?, ?, ?, 0)", (name, phash, salt))
        case "e":
            gid = input("enter the id of the group you want to edit:\n")
        case "r":
            ...

if __name__ == "__main__":
    main()
