#!/usr/bin/env python

"""
    Created by cengen on 9/18/17.
"""

from datetime import datetime
from os import getcwd, makedirs
from os.path import join as osjoin
from sys import argv, exit

from dateutil import parser
from exchangelib import DELEGATE, IMPERSONATION, Account, ServiceAccount, \
    EWSTimeZone, Configuration, Message, \
    attachments, errors, folders
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter

BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter

__DEBUG__ = False
__pass = False
_stderr = None
_stdout = None
__max_timeout__ = 10

accepted_commands = {
    "options": ["d", "p"],
    "inputs": ["user", "password", "type", "path_output", "win", "email", "start_date", "end_date", "auth_type",
               "service_endpoint", "exclude_folders", "include_folders", "local_root", "extensions", "timezone",
               "access_type", "max_timeout"]
}

usage = """
    Usage:
        python<version> <email> <password> <access type> <user> <win domain> \\
            <path output> <start date> <end date> <ews type> <exclude folders> <include folders>\\
            <local root> <extensions> <timezone>

        All the following accept -d for debug mode must be place directly after the script name
        python3 eectract.py -d <args>

        python3 eextract.py -pd email=user@mail.com access_type=DELEGATE path_output=./
        python3 eextract.py -pd user=superuser@mail.com email=impersonateduser@mail.com access_type=IMPERSONATION path_output=./

        To Exclude Folders/Include Folders
        python3 eextract.py -pd user=superuser@mail.com email=impersonateduser@mail.com\\
            access_type=IMPERSONATION path_output=./ exclude_folders=AllContacts include_folders=Location

        Note: Not all folders can be filtered out as they do not have a proper name. Check the exported folder structure
            after a extract to see what folders are there and to select the proper names for the folder.

        Available Inputs:
            {}
""".format(accepted_commands['inputs'])

import sys
import logging.handlers

log_file = osjoin(getcwd(), "eextract.log")
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


def connect(email, password, service_endpoint=None, auth_type=None, access_type=None, user=None, win_domain=None, *args,
            **kwargs):
    access_type = DELEGATE if "DELEGATE" in access_type else IMPERSONATION

    if user and win_domain:
        creds = ServiceAccount(username="{}\\{}".format(win_domain, user), password=password, max_wait=__max_timeout__)
    elif user and win_domain is None:
        creds = ServiceAccount(username=user, password=password, max_wait=__max_timeout__)
    else:
        creds = ServiceAccount(username=email, password=password, max_wait=__max_timeout__)

    if access_type is not None and auth_type is not None and service_endpoint is not None:
        conf = Configuration(service_endpoint=service_endpoint, credentials=creds, auth_type=auth_type)
        account = Account(primary_smtp_address=email, config=conf, autodiscover=False, access_type=access_type)
    else:
        account = Account(primary_smtp_address=email, autodiscover=True, credentials=creds)
    return account


def get_folder(_inbox, _command, abs_path, i_path):
    """
    Requires _inbox to be of the type folders.Folder or folders.Inbox
    :param i_path: Path of file structure
    :param abs_path: absolute path to file
    :param _inbox: Inbox object from exchanglib
    :param _command: command set to be used
    :return: None
    """
    i_path = i_path.split('/')[1:]
    i_path = osjoin(*i_path)

    if 'start_date' in _command.keys():
        start_date = parser.parse(_command['start_date'])
        start_date = start_date.replace(tzinfo=None)
    if 'end_date' in _command.keys():
        end_date = parser.parse(_command['end_date'])
        end_date = end_date.replace(tzinfo=None)

    for item in _inbox:
        if not isinstance(item, Message):
            continue
        if len(item.attachments) == 0 and "extensions" in _command.keys():
            continue
        elif "extensions" in _command.keys():
            _attachments = [_command["extensions"] in i.name for i in item.attachments]
            if not any(_attachments):
                continue

        date = parser.parse(str(item.datetime_sent))
        date = date.replace(tzinfo=None)

        if 'start_date' in _command.keys():
            if date < start_date:
                continue
        if 'end_date' in _command.keys():
            if date > end_date:
                continue

        try:
            item_path = osjoin(abs_path, i_path, "{}".format(_inbox.folder.name),
                               "{}{}".format(item.sender.email_address, item.datetime_sent))
        except AttributeError:
            item_path = osjoin(abs_path, i_path, "{}".format(_inbox.folder.name), "{}".format(item.datetime_sent))
        try:
            makedirs(item_path, mode=0o777)
        except FileExistsError:
            pass
        from html.parser import HTMLParser

        class MLStripper(HTMLParser):
            def __init__(self):
                self.reset()
                self.strict = False
                self.convert_charrefs = True
                self.fed = []

            def handle_data(self, d):
                self.fed.append(d)

            def get_data(self):
                return ''.join(self.fed)

        def strip_tags(html):
            s = MLStripper()
            s.feed(html)
            return s.get_data()

        with open(osjoin(item_path, "subject.txt"), "w") as subject_file:
            subject_file.write(item.subject if item.subject is not None else "")
        try:
            with open(osjoin(item_path, "body.txt"), "w") as body_file:
                body_file.write(strip_tags(item.body))
        except TypeError:
            with open(osjoin(item_path, "body.txt"), "w") as body_file:
                body_file.write(item.body if item.body is not None else "")

        def get_attachment(p, att):
            path_attachment = osjoin(p, "attachments")
            try:
                makedirs(path_attachment, mode=0o777)
            except FileExistsError:
                pass
            if isinstance(att, attachments.FileAttachment):
                with open(osjoin(path_attachment, att.name), "wb") as attach:
                    attach.write(att.content)
            elif isinstance(attachment, Message):
                with open(osjoin(path_attachment, att.name), "wb") as attach:
                    attach.write(att.item.subject)
                    attach.write(att.item.body)

        # write all attachments to file
        for attachment in item.attachments:
            if "extensions" in _command.keys():
                try:
                    if _command["extensions"] in attachment.name:
                        get_attachment(item_path, attachment)
                except TypeError as error:
                    print("Failed to get attachment as {}\nTrying again".format(error))
                    try:
                        if _command["extensions"] in attachment.content_type:
                            get_attachment(item_path, attachment)
                    except TypeError as err:
                        print("Failed to get attachment as {}".format(err))
            else:
                get_attachment(item_path, attachment)

        ewl_url = conn.protocol.service_endpoint
        ews_auth_type = conn.protocol.auth_type
        primary_smtp_address = conn.primary_smtp_address
        with open(osjoin(item_path, "sender_info.txt"), "w") as info_file:
            info_file.write(ewl_url + "\n")
            info_file.write(ews_auth_type + "\n")
            info_file.write(primary_smtp_address + "\n")


def handle_folder(folder, path):
    for file in folder.walk():
        if type(file) is folders.Folder or type(file) is folders.Inbox:
            handle_folder(file, path=path)
        d = file
        file = file.all()
        if "include_folders" in command.keys():
            include_folders = command['include_folders'].split(',')
            if any(str(d.name).startswith(t) for t in include_folders) \
                    or any(t in d.absolute for t in include_folders):
                pass
            else:
                continue
        if "exclude_folders" in command.keys():
            exclude_folders = command['exclude_folders'].split(',')
            if any(str(d.name).startswith(t) for t in exclude_folders) \
                    or any(t in d.absolute for t in exclude_folders):
                continue

        try:
            get_folder(_inbox=file, _command=command, abs_path=path, i_path=d.absolute)
        except errors.ErrorAccessDenied as deny:
            print("Failed to get folder {}\n\t\tReason: {}".format(file, deny))
    d_ = folder
    folder = folder.all()
    if "exclude_folders" in command.keys():
        exclude_folders = command['exclude_folders'].split(',')
        if any(str(d_.name).startswith(t) for t in exclude_folders) \
                or any(t in d_.absolute for t in exclude_folders):
            return
    if "include_folders" in command.keys():
        include_folders = command['include_folders'].split(',')
        if any(str(d_.name).startswith(t) for t in include_folders) \
                or any(t in d_.absolute for t in include_folders):
            pass
        else:
            return

    try:
        get_folder(_inbox=folder, _command=command, abs_path=path, i_path=d_.absolute)
    except errors.ErrorAccessDenied as deny:
        print("Failed to get folder {}\n\t\tReason: {}".format(folder, deny))


_options = {
    "p": _password
}

if __name__ == "__main__":
    start_time = datetime.now()

    command = {}

    if len(argv) > 1:
        if "-" in argv[1]:
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
            cmd = cmd.split("=")
            if "-" in cmd[0]:
                continue
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
            conn = connect(**command)

            root = osjoin(command["path_output"], "data")
            try:
                makedirs(root, mode=0o777)
            except FileExistsError:
                pass

            if 'timezone' in command.keys():
                local_time = EWSTimeZone.localzone() if command['timezone'].lower() == 'local' \
                    else EWSTimeZone.timezone(command['timezone'].lower())
            else:
                local_time = EWSTimeZone()
            for f in conn.root.walk():
                handle_folder(f, root)

            print("Time taken:" + str(datetime.now() - start_time))
            exit(0)
        print("Time taken:" + str(datetime.now() - start_time))
        exit(-1)
    else:
        print(usage)
        print("Time taken:" + str(datetime.now() - start_time))
        exit(-1)
