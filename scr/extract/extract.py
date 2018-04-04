#!/usr/bin/env python

"""
    Created by cengen on 9/18/17.
"""

from datetime import datetime
from os import getcwd
from os.path import join
from sys import argv, exit

from exchangelib import DELEGATE, IMPERSONATION, Account, ServiceAccount, \
    Configuration
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter

BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter

__DEBUG__ = False
__pass = False
_stderr = None
_stdout = None
__max_timeout__ = 10

accepted_commands = {
    "options": ["d", "p"],
    "inputs": ["user", "password", "access_type", "path_output", "server", "win", "email", "max_timeout"]
}

usage = """
    Extract.py accesses the given account and extracts the contacts from the recipient folder.
        It also outputs a full tree of the account as well.

    Usage:
        python<3> <Path to Location>extract.py <options> <email> <password> <access_type> <path_output>
        python3 ./extract.py -pd email=user@mail.com password=123456 access_type=DELEGATE path_output=./

        python3 <Path to Location>extract.py <options> <email> <password> <access_type> <path_output>
        python3 ./extract.py -d email=user@mail.com password=123456 access_type=DELEGATE path_output=./

    Available options:
        d toggles the debug functionality, it will output a log to the directory the script is run from and is called
            extract.log
        p will not allow password to be entered in the command line to prevent over the shoulder attacks,
            it will use the built in system to ask for a password to allow the user to enter the password without
            displaying it to screen

    Available inputs:
        {}
        email:email signifies the user's account to be used
            example: john@example.com
        password: password to be used for the account
        user: changes use based on if win option is set. When win is not set then it is used as the controlling account.
        win: uses the windowmain with user parameter to login
        path_output: tells the program where to store the log and data file when run.
        access_type: DELEGATE IMPERSONATION

""".format(accepted_commands["inputs"])

import sys
import logging.handlers

log_file = join(getcwd(), "extract.log")
log_level = logging.INFO

logger = logging.getLogger(__name__)
logger.setLevel(log_level)
handler = logging.handlers.TimedRotatingFileHandler(log_file, when='midnight', backupCount=3)
formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


class Log(object):
    def __init__(self, log, level):
        self.logger = log
        self.level = level

    def write(self, message):
        if message.rstrip() != "":
            self.logger.log(self.level, message.rstrip())

    def flush(self):
        pass


def _password():
    import getpass
    global __pass
    print("Please enter in your password.")
    __pass = getpass.getpass()
    print("You entered in a password.")


def connect_test(password, email, access_type, user=None, win=None, server=None, *args, **kwargs):
    if user and win:
        credentials = ServiceAccount(username="{}\\{}".format(user, win), password=password, max_wait=__max_timeout__)
    elif user and win is None:
        credentials = ServiceAccount(username=user, password=password, max_wait=__max_timeout__)
    else:
        credentials = ServiceAccount(username=email, password=password, max_wait=__max_timeout__)

    access_type = DELEGATE if "DELEGATE" in access_type else IMPERSONATION

    if server:
        config = Configuration(server=server, credentials=credentials)

        user_account = Account(primary_smtp_address=email,
                               credentials=credentials, autodiscover=False, access_type=access_type, config=config)
    else:
        user_account = Account(primary_smtp_address=email,
                               credentials=credentials, autodiscover=True, access_type=access_type)

    ewl_url = user_account.protocol.service_endpoint
    ews_auth_type = user_account.protocol.auth_type
    primary_smtp_address = user_account.primary_smtp_address

    return ewl_url, ews_auth_type, primary_smtp_address, user_account


_options = {
    "p": _password
}

if __name__ == "__main__":

    command = {}

    if len(argv) > 1:
        if "-" in argv[1]:
            print("An option was entered")
            for option in argv[1].replace("-", ""):
                if option in accepted_commands["options"]:
                    if option == "d":
                        logging.captureWarnings(True)
                        sys.stdout = Log(log=logger, level=log_level)
                        sys.stderr = Log(log=logger, level=log_level)
                    else:
                        _options[option]()
                else:
                    print("Selected Option {} is not valid.".format(option))
                    print(usage)
    if len(argv) >= 5:
        __pass_checked = False
        for cmd in argv[1:]:
            if "-" in cmd:
                continue
            cmd = cmd.split("=")
            if cmd[0] in accepted_commands["inputs"]:
                if __pass and not __pass_checked:
                    command['password'] = __pass
                    __pass_checked = True
                command[cmd[0]] = cmd[1]
            else:
                print("Bad Argument entered, ending program\t{}".format(cmd))
                break
        else:
            if "max_timeout" in command.keys():
                __max_timeout__ = command["max_timeout"]
            print("Starting extraction of data from {}".format(command["email"]))
            print("\tStarting test of connection")
            data = connect_test(**command)
            print("\tConnection success.")
            print(data)
            print("-" * 40)
            print("Starting Extraction")
            print("-" * 40)
            from os import makedirs
            try:
                makedirs(command["path_output"])
            except FileExistsError:
                pass
            with open(join(command['path_output'], "data.txt"), "a+") as file:
                file.write("Extract Starting @ {}\n".format(datetime.now().isoformat()))
                file.write("-" * 40)
                file.write("\n")
                file.write("Start of Extraction File\n")
                f = "Display Name: {}\tE-mail Address: {}"
                u = data[-1]
                # u = Account(primary_smtp_address=None, credentials=None)
                for folder in u.root.walk():
                    if "Recipient" in folder.name:
                        print("Found Recipient in folder name, extracting data to file")
                        for item in folder.all():
                            file.write("DisplayName: {} EmailAddress: {}".format(item.display_name,
                                                                                 [emailaddress.email for emailaddress in
                                                                                  item.email_addresses]))
                            file.write("\n")
                file.write(data[-1].root.tree())
                file.write("\n")
                file.write("-" * 40)
                file.write("\n")
                file.write("ewl_url: {} ews_auth_type: {} primary_smtp_address: {}\n".format(data[0], data[1], data[2]))
                file.write("End of Extraction\n")
                file.write("\n")
            print("ewl_url: {} ews_auth_type: {} primary_smtp_address: {}".format(data[0], data[1], data[2]))
            print("-" * 40)
            print("Finished Extraction")
            print("-" * 40)
            exit(0)
    else:
        print(usage)
        exit(-1)
