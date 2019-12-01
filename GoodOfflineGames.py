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

    def __init__(self, source_modules, authentication_providers) -> None:
        self.source_modules = source_modules
        self.authentication_providers = authentication_providers
        super().__init__()

    def get_next_source(self):
        for source, source_module in self.source_modules.items():
            if source_module.needs_authentication:
                for _, provider in self.authentication_providers.items():
                    for user, auth in provider.get_next_login(source):
                        yield source, user, getattr(source_module, source)(game_collection, user, auth)

    def update(self):
        exit_code = 0
        for sname, user, source in self.get_next_source():
            info("Updating Games from {} for user '{}'".format(sname, user))
            exit_code = max(source.update_database(['windows', 'linux'], ['en', 'de']), exit_code)
        return exit_code

    def download(self, path, groupsource=True):
        exit_code = 0
        for sname, user, source in self.get_next_source():
            info("Download Games from {} for user '{}'".format(sname, user))
            if groupsource:
                sdir = os.path.join(path, sname)
            else:
                sdir = path
            if not os.path.isdir(sdir):
                os.makedirs(sdir)
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
    update_parser.add_argument('game_source', action='store', help='id of game source', nargs='?', default=None)

    download_parser = cmd_parser.add_parser('download', help='Download games listed in the database')
    download_parser.add_argument('path', action='store', help='Destination directory for downloads')

    return parser.parse_args(argv[1:])


def login(game_source, auth_provider, source_modules: dict, authentication_providers: dict):
    if game_source not in source_modules.keys():
        error('Invalid game source: {}'.format(game_source))
        return 1
    source = getattr(source_modules[game_source], game_source)
    user, auth = source.interactive_login()
    if auth is not None:
        print('Please enter your {} credentials!'.format(game_source))
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
        client = GoodOfflineGames(source_modules, authentication_providers)
        if args.cmd == 'update':
            sys.exit(client.update())
        if args.cmd == 'download':
            sys.exit(client.download(args.path))
