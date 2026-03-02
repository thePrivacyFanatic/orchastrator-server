"""
a CLI for accessing the DB
has almost no error handeling as it (unlike instance_config.py) is not intended for production use
"""

import access
import dc


def start() -> access.DBAccess:
    """
    creates a dbaccess object as a user to a selectd group

    :return: Description
    :rtype: DBAccess
    """
    gid = input("enter the id of the group you will be accessing: ")
    username = input("enter the name of the user you'll be acting as: ")
    uid = int(input("enter the uid of the user: "))
    privilege = int(
        input("enter privilege value from 0 to 4 where 0 is admin and 4 is isolated: ")
    )
    acc = access.DBAccess(gid)
    acc.user = dc.User(uid=uid, name=username, privilege=dc.Privilege(privilege))
    return acc


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
                    print(acc.introduce().users)
                case "2":
                    print(
                        list(acc.sync(int(input("which sid to sync from?: ")))),
                    )
                case "3":
                    print(acc.introduce().objectives)
                case "4":
                    username = input("enter the username for the user: ")
                    privilege = dc.Privilege(
                        int(
                            input(
                                """enter privilege level of the user
                                                0: admin
                                                1: moderator
                                                2: publisher
                                                3: silenced
                                                4: isolated\n> """
                            )
                        )
                    )
                    password = input("enter the password of the user\n> ")
                    signal = acc.add_user(username, privilege, password)
                    print(signal.model_dump_json())
                case "5":
                    contents = input(
                        "what is the signal's content "
                        "(note it is encrypted serverside if internal)\n> "
                    )
                    mtype = dc.MessageType(
                        int(
                            input(
                                """what is the type of the message?
                                                2: internal
                                                1: external
                                                0: executive\n> """
                            )
                        )
                    )
                    signal = acc.save_signal(dc.Signal(content=contents, mtype=mtype))
                    print(f"saved signal {signal}")
                case "6":
                    path = input("enter the file path for the implementation file: ")
                    with open(path, "rb", encoding="UTF-8") as file:
                        implementation = file.read()
                    signal = acc.add_objective(
                        dc.Objective(oid=None, implementation=implementation)
                    )
                    print(signal.model_dump_json())
    except access.BanStop:
        print("you have been banned")


if __name__ == "__main__":
    mainloop(start())
