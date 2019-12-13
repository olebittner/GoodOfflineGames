#!/usr/bin/env python3
#
# Copyright (C) 2019  Ole Bittner
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import argparse
import importlib
import logging
import os
import pkgutil
import sys

import pymongo
from pymongo.errors import ServerSelectionTimeoutError

logging.basicConfig(level=logging.INFO)
info = logging.info
warn = logging.warning
debug = logging.debug
error = logging.error
log_exception = logging.exception


class GoodOfflineGames:

    def __init__(self, content_providers, authentication_providers, database_collection) -> None:
        self.content_providers = content_providers
        self.authentication_providers = authentication_providers
        self.collection = database_collection
        super().__init__()

    def get_next_content_provider(self, sources, authentications, users):
        for content_provider_name in sources:
            if content_provider_name in self.content_providers.keys():
                if self.content_providers[content_provider_name].needs_authentication:
                    for auth_provider_name in authentications:
                        if auth_provider_name in self.authentication_providers.keys():
                            for user, auth in self.authentication_providers[auth_provider_name]\
                                    .get_next_login(content_provider_name, users):
                                yield content_provider_name, user, \
                                      getattr(self.content_providers[content_provider_name],
                                              content_provider_name)(self.collection, user, auth)
                        else:
                            error('{} is not a valid authentication provider: {}', auth_provider_name,
                                  self.authentication_providers.keys())
                            return
                else:
                    yield content_provider_name, None, getattr(self.content_providers[content_provider_name],
                                                               content_provider_name)(self.collection, None, None)
            else:
                error('{} is not a valid content provider: {}', content_provider_name, self.content_providers.keys())
                return

    def update(self, content_provider, provider_source, users):
        exit_code = 0
        if not content_provider or len(content_provider) <= 0:
            content_provider = self.content_providers
        if not provider_source or len(provider_source) <= 0:
            provider_source = self.authentication_providers
        for sname, user, source in self.get_next_content_provider(content_provider, provider_source, users):
            info("Updating Games from {} for user '{}'".format(sname, user))
            exit_code = max(source.update_database(['windows', 'linux', 'android'], ['en', 'de']), exit_code)
        return exit_code

    def download(self, path, content_provider, provider_source, users, group_by_content_provider=True):
        exit_code = 0
        if not content_provider or len(content_provider) <= 0:
            content_provider = self.content_providers
        if not provider_source or len(provider_source) <= 0:
            provider_source = self.authentication_providers
        for sname, user, source in self.get_next_content_provider(content_provider, provider_source, users):
            info("Download Games from {} for user '{}'".format(sname, user))
            if group_by_content_provider:
                sdir = os.path.join(path, sname)
            else:
                sdir = path
            source.download(sdir)
        return exit_code


def parse_arguments(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', '--database', action='store', help='Specify a MongoDB using a Connection String',
                        default='mongodb://localhost:27017/')

    cmd_parser = parser.add_subparsers(dest='cmd', title='Commands', required=True)
    login_parser = cmd_parser.add_parser('login', help='Login to one of the game sources')
    login_parser.add_argument('action', choices=['add', 'remove'])
    login_parser.add_argument('auth', action='store',
                              help='specify the authentication provider to store the credentials', default=None)
    login_parser.add_argument('content', action='store', help='specify the content provider to authenticate',
                              default=None)

    update_parser = cmd_parser.add_parser('update', help='Update game database')
    update_parser.add_argument('-c', '--content', action='store', help='specify one or more content providers',
                               nargs='+', default=None)
    update_parser.add_argument('-a', '--auth', help='specify one or more authentication providers',
                               nargs='+', default=None)
    update_parser.add_argument('-u', '--user', action='store', help='specify one or more users',
                               nargs='+', default=None)

    download_parser = cmd_parser.add_parser('download', help='Download games listed in the database')
    download_parser.add_argument('-p', '--path', action='store', help='Destination directory for downloads',
                                 default='Games')
    download_parser.add_argument('-c', '--content', action='store', help='specify one or more content providers',
                                 nargs='+', default=None)
    download_parser.add_argument('-a', '--auth', help='specify one or more authentication providers',
                                 nargs='+', default=None)
    download_parser.add_argument('-u', '--user', action='store', help='specify one or more users',
                                 nargs='+', default=None)

    return parser.parse_args(argv[1:])


def login(content_provider, auth_provider, content_providers: dict, auth_providers: dict):
    if content_provider not in content_providers.keys():
        error('Invalid game source: {}'.format(content_provider))
        return 1
    source = getattr(content_providers[content_provider], content_provider)
    print('Please enter your {} credentials!'.format(content_provider))
    user, auth = source.interactive_login()
    if auth is not None:
        auth_providers[auth_provider].save_authentication(content_provider, user, auth)
    else:
        error('Login failed!')
        return 1


if __name__ == '__main__':
    args = parse_arguments(sys.argv)
    client = pymongo.MongoClient(args.db, serverSelectionTimeoutMS=5000)

    try:
        client.server_info()
    except ServerSelectionTimeoutError as err:
        error("Could not connect to database")
        debug(err)
        sys.exit(1)

    database = client['GoodOfflineGames']
    game_collection = database['Games']

    info('importing content providers...')
    content_providers = {}
    for finder, name, ispkg in pkgutil.iter_modules(['content_providers']):
        debug('importing ' + name)
        module = importlib.import_module('content_providers.' + name)
        content_providers[name] = module
    info('successfully imported {} content providers'.format(len(content_providers)))

    info('importing authentication providers...')
    authentication_providers = {}
    for finder, name, ispkg in pkgutil.iter_modules(['authentication_providers']):
        debug('importing ' + name)
        module = importlib.import_module('authentication_providers.' + name)
        authentication_providers[name] = (getattr(module, name)())
    info('successfully imported {} providers'.format(len(authentication_providers)))

    if args.cmd == 'login':
        if args.auth not in authentication_providers.keys():
            error('Invalid authentication provider: {}'.format(args.auth))
            sys.exit(1)
        else:
            if args.action == 'add':
                sys.exit(login(args.content, args.auth, content_providers, authentication_providers))
            elif args.action == 'remove':
                sys.exit(authentication_providers[args.auth_provider]
                         .remove_authentication(args.game_source, input("Username to remove: ")))
    else:
        client = GoodOfflineGames(content_providers, authentication_providers, game_collection)
        if args.cmd == 'update':
            sys.exit(client.update(args.content, args.auth, args.user))
        if args.cmd == 'download':
            sys.exit(client.download(args.path, args.content, args.auth, args.user))
