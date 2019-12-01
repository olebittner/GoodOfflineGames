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
from configparser import ConfigParser

FILE = 'authentication.file'

class File:
    def get_next_login(self, source_id):
        config = ConfigParser()
        config.read(FILE)
        if source_id in config.sections():
            for entry in config.options(source_id):
                yield entry, config.get(source_id, entry)

    def save_authentication(self, source_id, user, auth):
        config = ConfigParser()
        config.read(FILE)
        if source_id not in config.sections():
            config.add_section(source_id)

        config.set(source_id, user, auth)
        with open(FILE, 'w') as f:
            config.write(f)
        return 0

    def remove_authentication(self, source_id, user):
        config = ConfigParser()
        config.read(FILE)
        if source_id in config.sections():
            config.remove_option(source_id, user)

        with open(FILE, 'w') as f:
            config.write(f)
