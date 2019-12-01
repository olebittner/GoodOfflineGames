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
