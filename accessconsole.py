"""
a CLI for accessing the DB
has almost no error handeling as it (unlike instance_config.py) is not intended for production use
"""

from dataclasses import fields
import sqlite3
from typing import Iterable, Sequence
from pydantic import BaseModel
import access
from dc import MessageType, Objective, Privilege, Signal, User
from main import BanStop


def start() -> access.DBAccess:
    """
    creates a dbaccess object as a user to a selectd group

    :return: Description
    :rtype: DBAccess
    """
    gid = input("enter the id of the group you will be accessing: ")
    username = input("enter the name of the user you'll be acting as: ")
    uid = int(input("enter the uid of the user: "))
    privlage = int(
        input("enter privlage value from 0 to 4 where 0 is admin and 4 is isolated: ")
    )
    return access.DBAccess(
        User(uid=uid, name=username, privilege=Privilege(privlage)),
        sqlite3.connect(f"db/{gid}.db"),
    )


def mainloop(acc: access.DBAccess) -> None:
    """
    cli loop asking what to do as the user and executing

    :param acc: the DBaccess manager that is utilized when acting on the DB
    :type acc: access.DBAccess
    """
    try:
        while True:
            match input(
                """
                        choose what you would like to do:
                        1. print all users
                        2. print all signals after sid
                        3. print info of all objectives
                        4. create and add a user
                        5. create and add a signal
                        6. create and add an objective
                        0. exit\n> """
            ):
                case "0":
                    break
                case "1":
                    _dump_data_class_list(acc.introduce().users, (3, 16, 23))
                case "2":
                    _dump_data_class_list(
                        list(acc.sync(int(input("which sid to sync from?: ")))),
                        (4, 19, 3, 16, 5),
                    )
                case "3":
                    _dump_data_class_list(acc.introduce().objectives, (3, 16, 0))
                case "4":
                    username = input("enter the username for the user: ")
                    privlage = Privilege(
                        int(
                            input(
                                """enter privlage level of the user
                                                0: admin
                                                1: moderator
                                                2: publisher
                                                3: silenced
                                                4: isolated\n> """
                            )
                        )
                    )
                    password = input("enter the password of the user\n> ")
                    signal = acc.add_user(username, privlage, password)
                    print(signal.model_dump_json())
                case "5":
                    contents = input(
                        "what is the signal's content "
                        "(note it is encrypted serverside if internal)\n> "
                    )
                    mtype = MessageType(
                        int(
                            input(
                                """what is the type of the message?
                                                2: internal
                                                1: external
                                                0: executive\n> """
                            )
                        )
                    )
                    signal = acc.save_signal(Signal(content=contents, mtype=mtype))
                    print(f"saved signal {signal}")
                case "6":
                    name = input("enter the display name for the objective: ")
                    path = input("enter the file path for the implementation file: ")
                    with open(path, "rb", encoding="UTF-8") as file:
                        implementation = file.read()
                    signal = acc.add_objective(
                        Objective(oid=None, implementation=implementation)
                    )
                    print(signal.model_dump_json())
    except BanStop:
        print("you have been banned")


def _dump_data_class_list(
    objects: Sequence[BaseModel], paddings: tuple[int, ...]
) -> None:
    """
    prints a sequence of dataclass objects as a table

    :param objects: list of objects of the type
    :type objects: Sequence[DataClass]
    """
    if len(objects) == 0:
        return
    _pad_tuple(map(lambda f: f.name, fields(objects[0])), paddings)
    for o in objects:
        _pad_tuple([i[1] for i in o.model_dump().values()], paddings)


def _pad_tuple(t: Iterable, paddings: tuple[int, ...]) -> None:
    for i, p in zip(t, paddings):
        print(f"{str(i):<{p}}", end="|")
    print()


if __name__ == "__main__":
    mainloop(start())
