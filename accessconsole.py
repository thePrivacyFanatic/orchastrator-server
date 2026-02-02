"""
a CLI for accessing the DB
has no error handeling as it is not intended for production use
"""
import sqlite3
import access
from dc import Privlage, User


def start() -> access.DBAccess:
    """
    creates a dbaccess object as a user to a selectd group
    
    :return: Description
    :rtype: DBAccess
    """
    gid = int(input("enter the id of the group you will be accessing"))
    username = input("enter the name of the user you'll be acting as")
    uid = int(input("enter the uid of the user"))
    privlage = int(input("enter privlage value from 0 to 4 where 0 is admin and 4 is isolated"))
    return access.DBAccess(User(uid, username, Privlage(privlage)), sqlite3.connect(f"db/{gid}.db"))


def mainloop(acc: access.DBAccess) -> None:
    """
    cli loop asking what to do as the user and executing
    
    :param acc: the DBaccess manager that is utilized when acting on the DB
    :type acc: access.DBAccess
    """
    while True:
        match input("""
                    choose what you would like to do:
                    1. print all users
                    2. print all signals after sid
                    3. print info of an objective"""):
            case "1":
                print(acc.introduce()[0])
            case "2":
                print(acc.sync(int(input())))
            case "3":
                print(acc.introduce()[1])


if __name__ == "__main__":
    mainloop(start())
