import sqlite3
import random
from secrets import token_hex
from argon2 import PasswordHasher


def main():
    action = input("Orchasrator serverside setup, what would you like to do?\n"
                    "n) create a new instance\n"
                    "e) edit an existing instance\n"
                    "r) delete a database")
    match action.casefold().strip():
        case "n":
            id = random.randbytes(8).hex()
            print("generated instance ID " + id)
            with sqlite3.connect(f"./db/{id}.db") as db:
                db.executescript("""
                    CREATE TABLE users ( id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, salt TEXT, hash TEXT );
                    CREATE TABLE signals ( id INTEGER PRIMARY KEY  AUTOINCREMENT, timestamp INTEGER, sender INTEGER, contents TEXT ); """
                    )
                print("created tables, starting to add users")
                hasher = PasswordHasher()
                while True:
                    name = input("type a username, leave empty to finish")
                    if name == "": break
                    password = input("type a password or passphrase")
                    salt = token_hex(16)
                    phash = PasswordHasher.hash(hasher, password=password, salt=salt.encode())

        case "e":
            ...
        case "r":
            ...


if __name__ == "__main__":
    main()

