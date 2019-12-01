from urllib.parse import urlencode
from urllib.request import Request

import pymongo.collection
import getpass
import logging
import time
import os
import sys
import threading
import logging
import contextlib
import json
import html5lib
import pprint
import time
import zipfile
import hashlib
import getpass
import codecs
import io
import datetime
import shutil
import socket
import xml.etree.ElementTree
from queue import Queue
import http.cookiejar as cookiejar
from http.client import BadStatusLine
from urllib.parse import urlparse, urlencode, unquote
from urllib.request import HTTPCookieProcessor, HTTPError, URLError, build_opener, Request
from itertools import zip_longest
from io import StringIO
import codecs
try:
    import cPickle as pickle
except ImportError:
    import pickle

info = logging.info
warn = logging.warning
debug = logging.debug
error = logging.error
log_exception = logging.exception

GOG_HOME_URL = r'https://www.gog.com'
GOG_ACCOUNT_URL = r'https://www.gog.com/account'
GOG_LOGIN_URL = r'https://login.gog.com/login_check'

HTTP_FETCH_DELAY = 1   # in seconds
HTTP_RETRY_DELAY = 5   # in seconds
HTTP_RETRY_COUNT = 3
HTTP_GAME_DOWNLOADER_THREADS = 4
HTTP_PERM_ERRORCODES = (404, 403, 503)

global_cookies = cookiejar.CookieJar()
cookieproc = HTTPCookieProcessor(global_cookies)
opener = build_opener(cookieproc)
treebuilder = html5lib.treebuilders.getTreeBuilder('etree')
parser = html5lib.HTMLParser(tree=treebuilder, namespaceHTMLElements=False)


def request(url, args=None, byte_range=None, retries=HTTP_RETRY_COUNT, delay=HTTP_FETCH_DELAY):
    """Performs web request to url with optional retries, delay, and byte range.
    """
    _retry = False
    time.sleep(delay)

    try:
        if args is not None:
            enc_args = urlencode(args)
            enc_args = enc_args.encode('ascii')  # needed for Python 3
        else:
            enc_args = None
        req = Request(url, data=enc_args)
        if byte_range is not None:
            req.add_header('Range', 'bytes=%d-%d' % byte_range)
        page = opener.open(req)
    except (HTTPError, URLError, socket.error, BadStatusLine) as e:
        if isinstance(e, HTTPError):
            if e.code in HTTP_PERM_ERRORCODES:  # do not retry these HTTP codes
                warn('request failed: %s.  will not retry.', e)
                raise
        if retries > 0:
            _retry = True
        else:
            raise

        if _retry:
            warn('request failed: %s (%d retries left) -- will retry in %ds...' % (e, retries, HTTP_RETRY_DELAY))
            return GOG.request(url=url, args=args, byte_range=byte_range, retries=retries - 1, delay=HTTP_RETRY_DELAY)

    return contextlib.closing(page)

class GOG:

    def __init__(self, collection: pymongo.collection, auth_blob) -> None:
        self.game_collection = collection
        self.auth = auth_blob
        super().__init__()

    @staticmethod
    def needs_authentication():
        return True

    @staticmethod
    def interactive_login():
        login_data = {'user': input("Username: "), 'passwd': getpass.getpass(), 'auth_url': None, 'login_token': None,
                      'two_step_url': None, 'two_step_token': None, 'two_step_security_code': None,
                      'login_success': False}

        info("attempting gog login as '{}' ...".format(login_data['user']))

        # fetch the auth url
        with request(GOG_HOME_URL, delay=0) as page:
            etree = html5lib.parse(page, namespaceHTMLElements=False)
            for elm in etree.findall('.//script'):
                if elm.text is not None and 'GalaxyAccounts' in elm.text:
                    login_data['auth_url'] = elm.text.split("'")[3]
                    break

        # fetch the login token
        with request(login_data['auth_url'], delay=0) as page:
            etree = html5lib.parse(page, namespaceHTMLElements=False)
            # Bail if we find a request for a reCAPTCHA
            if len(etree.findall('.//div[@class="g-recaptcha form__recaptcha"]')) > 0:
                error("cannot continue, gog is asking for a reCAPTCHA :(  try again in a few minutes.")
                return
            for elm in etree.findall('.//input'):
                if elm.attrib['id'] == 'login__token':
                    login_data['login_token'] = elm.attrib['value']
                    break

        # perform login and capture two-step token if required
        with request(GOG_LOGIN_URL, delay=0, args={'login[username]': login_data['user'],
                                                   'login[password]': login_data['passwd'],
                                                   'login[login]': '',
                                                   'login[_token]': login_data['login_token']}) as page:
            etree = html5lib.parse(page, namespaceHTMLElements=False)
            if 'two_step' in page.geturl():
                login_data['two_step_url'] = page.geturl()
                for elm in etree.findall('.//input'):
                    if elm.attrib['id'] == 'second_step_authentication__token':
                        login_data['two_step_token'] = elm.attrib['value']
                        break
            elif 'on_login_success' in page.geturl():
                login_data['login_success'] = True

        # perform two-step if needed
        if login_data['two_step_url'] is not None:
            login_data['two_step_security_code'] = input("enter two-step security code: ")

            # Send the security code back to GOG
            with request(login_data['two_step_url'], delay=0,
                         args={'second_step_authentication[token][letter_1]': login_data['two_step_security_code'][0],
                               'second_step_authentication[token][letter_2]': login_data['two_step_security_code'][1],
                               'second_step_authentication[token][letter_3]': login_data['two_step_security_code'][2],
                               'second_step_authentication[token][letter_4]': login_data['two_step_security_code'][3],
                               'second_step_authentication[send]': "",
                               'second_step_authentication[_token]': login_data['two_step_token']}) as page:
                if 'on_login_success' in page.geturl():
                    login_data['login_success'] = True

        # save cookies on success
        if login_data['login_success']:
            info('login successful!')
            return login_data['user'], codecs.encode(pickle.dumps(list(global_cookies)), "base64").decode()
        else:
            error('login failed, verify your username/password and try again.')

