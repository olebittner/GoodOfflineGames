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

logging.basicConfig(level=logging.DEBUG)
info = logging.info
warn = logging.warning
debug = logging.debug
error = logging.error
log_exception = logging.exception


class GoodOfflineGames:

    def __init__(self, source_modules, authentication_providers, database_collection) -> None:
        self.source_modules = source_modules
        self.authentication_providers = authentication_providers
        self.collection = database_collection
        super().__init__()

    def get_next_source(self, sources, authentications, users):
        for source_name in sources:
            if source_name in self.source_modules.keys():
                if self.source_modules[source_name].needs_authentication:
                    for provider_name in authentications:
                        if provider_name in self.authentication_providers.keys():
                            for user, auth in self.authentication_providers[provider_name].get_next_login(source_name, users):
                                yield source_name, user, getattr(self.source_modules[source_name], source_name)(self.collection, user, auth)
                        else:
                            error('{} is not a valid authentication provider: {}', provider_name,
                                  self.authentication_providers.keys())
                            return
                else:
                    yield source_name, None, getattr(self.source_modules[source_name], source_name)(self.collection, None, None)
            else:
                error('{} is not a valid source: {}', source_name, self.source_modules.keys())
                return

    def update(self, game_source, provider_source, users):
        exit_code = 0
        if not game_source or len(game_source) <= 0:
            game_source = self.source_modules
        if not provider_source or len(provider_source) <= 0:
            provider_source = self.authentication_providers
        for sname, user, source in self.get_next_source(game_source, provider_source, users):
            info("Updating Games from {} for user '{}'".format(sname, user))
            exit_code = max(source.update_database(['windows', 'linux', 'android'], ['en', 'de']), exit_code)
        return exit_code

    def download(self, path, game_source, provider_source, users, groupsource=True):
        exit_code = 0
        if not game_source or len(game_source) <= 0:
            game_source = self.source_modules
        if not provider_source or len(provider_source) <= 0:
            provider_source = self.authentication_providers
        for sname, user, source in self.get_next_source(game_source, provider_source, users):
            info("Download Games from {} for user '{}'".format(sname, user))
            if groupsource:
                sdir = os.path.join(path, sname)
            else:
                sdir = path
            source.download(sdir)
        return exit_code


def parse_arguments(argv):
    parser = argparse.ArgumentParser()

    cmd_parser = parser.add_subparsers(dest='cmd', title='Commands', required=True)
    login_parser = cmd_parser.add_parser('login', help='Login to one of the game sources')
    login_parser.add_argument('action', choices=['add', 'remove'])
    login_parser.add_argument('auth_provider', action='store', help='id of authentication providers',
                              default=None)
    login_parser.add_argument('game_source', action='store', help='id of game source', default=None)

    update_parser = cmd_parser.add_parser('update', help='Update game database')
    update_parser.add_argument('-s', '--source', action='store', help='list of game source', nargs='+', default=None)
    update_parser.add_argument('-a', '--authentication', help='list of authentication providers', nargs='+',
                               default=None)
    update_parser.add_argument('-u', '--user', action='store', help='list of users', nargs='+', default=None)

    download_parser = cmd_parser.add_parser('download', help='Download games listed in the database')
    download_parser.add_argument('-p','--path', action='store', help='Destination directory for downloads', default='Games')
    download_parser.add_argument('-s', '--source', action='store', help='list of game source', nargs='+', default=None)
    download_parser.add_argument('-a', '--authentication', help='list of authentication providers', nargs='+',
                                 default=None)
    download_parser.add_argument('-u', '--user', action='store', help='list of users', nargs='+', default=None)

    return parser.parse_args(argv[1:])


def login(game_source, auth_provider, source_modules: dict, authentication_providers: dict):
    if game_source not in source_modules.keys():
        error('Invalid game source: {}'.format(game_source))
        return 1
    source = getattr(source_modules[game_source], game_source)
    print('Please enter your {} credentials!'.format(game_source))
    user, auth = source.interactive_login()
    if auth is not None:
        authentication_providers[auth_provider].save_authentication(game_source, user, auth)
    else:
        error('Login failed!')
        return 1


if __name__ == '__main__':
    database = pymongo.MongoClient('mongodb://localhost:27017/')['GoodOfflineGames']
    game_collection = database['Games']

    info('importing game sources...')
    source_modules = {}
    for finder, name, ispkg in pkgutil.iter_modules(['sources']):
        debug('importing ' + name)
        module = importlib.import_module('sources.' + name)
        source_modules[name] = module
    info('successfully imported {} sources'.format(len(source_modules)))

    info('importing authentication providers...')
    authentication_providers = {}
    for finder, name, ispkg in pkgutil.iter_modules(['authentication_providers']):
        debug('importing ' + name)
        module = importlib.import_module('authentication_providers.' + name)
        authentication_providers[name] = (getattr(module, name)())
    info('successfully imported {} providesr'.format(len(authentication_providers)))

    args = parse_arguments(sys.argv)

    if args.cmd == 'login':
        if args.auth_provider not in authentication_providers.keys():
            error('Invalid authentication provider: {}'.format(args.auth_provider))
            sys.exit(1)
        else:
            if args.action == 'add':
                sys.exit(login(args.game_source, args.auth_provider, source_modules, authentication_providers))
            elif args.action == 'remove':
                sys.exit(authentication_providers[args.auth_provider]
                         .remove_authentication(args.game_source, input("Username to remove: ")))
    else:
        client = GoodOfflineGames(source_modules, authentication_providers, game_collection)
        if args.cmd == 'update':
            sys.exit(client.update(args.source, args.authentication, args.user))
        if args.cmd == 'download':
            sys.exit(client.download(args.path, args.source, args.authentication, args.user))
