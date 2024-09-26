#!/usr/bin/env python3
#

import asyncio

import imapclient.exceptions
import tornado
import os.path

from email import message_from_bytes
from imapclient import IMAPClient

from tornado.options import define, options, parse_command_line

from typing import Dict
import credentials

import logging
from tornado.log import enable_pretty_logging

define("port", default=8888, help="run on the given port", type=int)
define("secret", default="TideWeb", help="encryption secret", type=str)
define("debug", default=True, help="run in debug mode")

logging.basicConfig(
    filename='logs/tide.log',
    level=logging.INFO,
    format='%(levelname)s: %(asctime)s - %(message)s',
)
enable_pretty_logging()

def parse_rfc822_header(header: bytes) -> Dict[str, str]:
    # Parse the RFC822 header string into an email message object
    email_message = message_from_bytes(header)

    # Convert the email message headers into a dictionary
    header_dict = {}

    for key, value in email_message.items():
        header_dict[key] = value

    return header_dict


def parse_rfc822_body(raw_email: bytes) -> str:
    # Parse the raw email string into an EmailMessage object
    email_message = message_from_bytes(raw_email)

    # Initialize a variable for the body content
    body = None

    # Check if the email is multipart (i.e., it could have text and HTML parts)
    if email_message.is_multipart():
        # Loop through the different parts of the email
        for part in email_message.walk():
            # We look for the plain text part of the email
            if part.get_content_type() == 'text/plain':
                body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
                break
    else:
        # If the email is not multipart, just get the payload (the body)
        body = email_message.get_payload(decode=True).decode(email_message.get_content_charset() or 'utf-8')

    return body

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("index.html", error = "")

class MailboxHandler(tornado.web.RequestHandler):
    def post(self):
        try:
            with IMAPClient(host="mail.livemail.co.uk") as client:
                client.login(self.get_argument("username"), self.get_argument("password"))
                self.set_signed_cookie("tide_user", tornado.escape.json_encode(self.get_argument("username")))

                logging.info("User " + self.get_argument("username") + " logged in")

                credentials.store_credentials(
                    "mail.livemail.co.uk",
                    self.get_argument("username"),
                    self.get_argument("password"),
                    options.secret,
                )

                mailbox_list_response = client.list_folders()
                mailboxes = []
                for (flags, delimiter, name) in mailbox_list_response:
                    mailboxes.append(name)
            self.render("mail.html", mailboxes=mailboxes)
        except imapclient.exceptions.IMAPClientError:
            self.render("index.html", error="incorrect username or password")

class FolderHandler(tornado.web.RequestHandler):
    def get(self, folder):
        email = self.get_signed_cookie("tide_user")
        if not email:
            self.render("index.html", error="Something went wrong getting cookie data")
        imap_server, email, decrypted_password = credentials.retrieve_credentials(
            tornado.escape.json_decode(email),
            encryption_key=options.secret,
        )
        try:
            with IMAPClient("mail.livemail.co.uk") as client:
                client.login(email, decrypted_password)
                mailbox_list_response = client.list_folders()
                mailboxes = []
                for (flags, delimiter, name) in mailbox_list_response:
                    mailboxes.append(name)
                select_response = client.select_folder(folder)
                email_headers = []
                message_count = select_response.get(b'EXISTS')
                logging.info("User " + email + " has " + str(message_count) + " emails")
                if message_count != 0:
                    messages = client.search(["NOT", "DELETED"])
                    response = client.fetch(messages, ["FLAGS", "INTERNALDATE", "RFC822.HEADER", "RFC822.SIZE"])
                    for message_id, data in response.items():
                        email_headers.append((parse_rfc822_header(data[b'RFC822.HEADER']), None, message_id))

                self.render("emails.html", error=None, folder=folder, mailboxes=mailboxes, emails=email_headers)
        except imapclient.exceptions.IMAPClientError:
            self.render("emails.html", error="could not fetch emails from " + folder)

class EmailHandler(tornado.web.RequestHandler):
    def get(self, folder, mail_uid):
        mail_user = self.get_signed_cookie("tide_user")
        if not mail_user:
            self.render("index.html", error="Something went wrong getting cookie data")
        imap_server, mail_user, decrypted_password = credentials.retrieve_credentials(
            tornado.escape.json_decode(mail_user),
            encryption_key=options.secret,
        )
        try:
            with IMAPClient("mail.livemail.co.uk") as client:
                client.login(mail_user, decrypted_password)
                mailbox_list_response = client.list_folders()
                mailboxes = []
                for (flags, delimiter, name) in mailbox_list_response:
                    mailboxes.append(name)
                select_response = client.select_folder(folder)
                email_headers = []
                if select_response.get(b'EXISTS') != 0:
                    response = client.fetch([str(mail_uid)], ["RFC822"])
                    for message_id, data in response.items():
                        email_headers.append(
                            (
                                parse_rfc822_header(data[b'RFC822']),
                                parse_rfc822_body(data[b'RFC822']),
                                message_id
                            )
                        )

                self.render("emails.html", error=None, folder=folder, mailboxes=mailboxes, emails=email_headers)
        except imapclient.exceptions.IMAPClientError:
            self.render("emails.html", error="could not fetch emails from " + folder)

async def main():
    parse_command_line()
    logging.info("Starting Tornado web server on port " + str(options.port))
    app = tornado.web.Application(
        [
            (r"/", MainHandler),
            (r"/mail", MailboxHandler),
            (r"/mail/folder/([^/]+)", FolderHandler),
            (r"/mail.folder/([^/]+)/(.+)", EmailHandler),
        ],
        cookie_secret="_tide_783_cookie",
        template_path=os.path.join(os.path.dirname(__file__), "templates"),
        static_path=os.path.join(os.path.dirname(__file__), "static"),
        xsrf_cookies=True,
        debug=options.debug,
    )
    app.listen(options.port)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())