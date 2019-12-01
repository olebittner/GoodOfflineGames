from urllib.parse import urlencode
from urllib.request import Request, OpenerDirector

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

needs_authentication = True

# GOG URLs
GOG_HOME_URL = r'https://www.gog.com'
GOG_ACCOUNT_URL = r'https://www.gog.com/account'
GOG_LOGIN_URL = r'https://login.gog.com/login_check'

# GOG Constants
GOG_MEDIA_TYPE_GAME  = '1'
GOG_MEDIA_TYPE_MOVIE = '2'

# HTTP request settings
HTTP_FETCH_DELAY = 1   # in seconds
HTTP_RETRY_DELAY = 5   # in seconds
HTTP_RETRY_COUNT = 3
HTTP_GAME_DOWNLOADER_THREADS = 4
HTTP_PERM_ERRORCODES = (404, 403, 503)

# Save manifest data for these os and lang combinations
DEFAULT_OS_LIST = ['windows']
DEFAULT_LANG_LIST = ['en']

# These file types don't have md5 data from GOG
SKIP_MD5_FILE_EXT = ['.txt', '.zip']

# Language table that maps two letter language to their unicode gogapi json name
LANG_TABLE = {'en': u'English',   # English
              'bl': u'\u0431\u044a\u043b\u0433\u0430\u0440\u0441\u043a\u0438',  # Bulgarian
              'ru': u'\u0440\u0443\u0441\u0441\u043a\u0438\u0439',              # Russian
              'gk': u'\u0395\u03bb\u03bb\u03b7\u03bd\u03b9\u03ba\u03ac',        # Greek
              'sb': u'\u0421\u0440\u043f\u0441\u043a\u0430',                    # Serbian
              'ar': u'\u0627\u0644\u0639\u0631\u0628\u064a\u0629',              # Arabic
              'br': u'Portugu\xeas do Brasil',  # Brazilian Portuguese
              'jp': u'\u65e5\u672c\u8a9e',      # Japanese
              'ko': u'\ud55c\uad6d\uc5b4',      # Korean
              'fr': u'fran\xe7ais',             # French
              'cn': u'\u4e2d\u6587',            # Chinese
              'cz': u'\u010desk\xfd',           # Czech
              'hu': u'magyar',                  # Hungarian
              'pt': u'portugu\xeas',            # Portuguese
              'tr': u'T\xfcrk\xe7e',            # Turkish
              'sk': u'slovensk\xfd',            # Slovak
              'nl': u'nederlands',              # Dutch
              'ro': u'rom\xe2n\u0103',          # Romanian
              'es': u'espa\xf1ol',      # Spanish
              'pl': u'polski',          # Polish
              'it': u'italiano',        # Italian
              'de': u'Deutsch',         # German
              'da': u'Dansk',           # Danish
              'sv': u'svenska',         # Swedish
              'fi': u'Suomi',           # Finnish
              'no': u'norsk',           # Norsk
              }

VALID_OS_TYPES = ['windows', 'linux', 'mac']
VALID_LANG_TYPES = list(LANG_TABLE.keys())

treebuilder = html5lib.treebuilders.getTreeBuilder('etree')
parser = html5lib.HTMLParser(tree=treebuilder, namespaceHTMLElements=False)


def request(url, args=None, byte_range=None, retries=HTTP_RETRY_COUNT, delay=HTTP_FETCH_DELAY, cookies=cookiejar.CookieJar()):
    """Performs web request to url with optional retries, delay, and byte range.
    """
    _retry = False
    time.sleep(delay)

    cookieproc = HTTPCookieProcessor(cookies)
    opener = build_opener(cookieproc)

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
            return request(url=url, args=args, byte_range=byte_range, retries=retries - 1, delay=HTTP_RETRY_DELAY)

    return contextlib.closing(page)


class AttrDict(dict):
    def __init__(self, **kw):
        self.update(kw)

    def __getattr__(self, key):
        return self[key]

    def __setattr__(self, key, val):
        self[key] = val


class ConditionalWriter(object):
    """File writer that only updates file on disk if contents chanaged"""

    def __init__(self, filename):
        self._buffer = None
        self._filename = filename

    def __enter__(self):
        self._buffer = tmp = StringIO()
        return tmp

    def __exit__(self, _exc_type, _exc_value, _traceback):
        tmp = self._buffer
        if tmp:
            pos = tmp.tell()
            tmp.seek(0)

            file_changed = not os.path.exists(self._filename)
            if not file_changed:
                with codecs.open(self._filename, 'r', 'utf-8') as orig:
                    for (new_chunk, old_chunk) in zip_longest(tmp, orig):
                        if new_chunk != old_chunk:
                            file_changed = True
                            break

            if file_changed:
                with codecs.open(self._filename, 'w', 'utf-8') as overwrite:
                    tmp.seek(0)
                    shutil.copyfileobj(tmp, overwrite)


def open_notrunc(name, bufsize=4*1024):
    flags = os.O_WRONLY | os.O_CREAT
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY  # windows
    fd = os.open(name, flags, 0o666)
    return os.fdopen(fd, 'wb', bufsize)


class GOG:

    def __init__(self, collection: pymongo.collection, user, auth_blob) -> None:
        self.game_collection: pymongo.collection = collection
        self.user = user
        self.cookies = self.recreate_cookiejar(auth_blob)
        super().__init__()

    @staticmethod
    def recreate_cookiejar(base64):
        jar = cookiejar.CookieJar()
        cookies = pickle.loads(codecs.decode(base64.encode(), 'base64'))
        for cookie in cookies:
            jar.set_cookie(cookie)
        return jar

    @staticmethod
    def interactive_login():
        login_data = {'user': input("Username: "), 'passwd': getpass.getpass(), 'auth_url': None, 'login_token': None,
                      'two_step_url': None, 'two_step_token': None, 'two_step_security_code': None,
                      'login_success': False}

        info("attempting gog login as '{}' ...".format(login_data['user']))

        cookies = cookiejar.CookieJar()
        # fetch the auth url
        with request(GOG_HOME_URL, delay=0, cookies=cookies) as page:
            etree = html5lib.parse(page, namespaceHTMLElements=False)
            for elm in etree.findall('.//script'):
                if elm.text is not None and 'GalaxyAccounts' in elm.text:
                    login_data['auth_url'] = elm.text.split("'")[3]
                    break

        # fetch the login token
        with request(login_data['auth_url'], delay=0, cookies=cookies) as page:
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
                                                   'login[_token]': login_data['login_token']},
                     cookies=cookies) as page:
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
                               'second_step_authentication[_token]': login_data['two_step_token']},
                         cookies=cookies) as page:
                if 'on_login_success' in page.geturl():
                    login_data['login_success'] = True

        # save cookies on success
        if login_data['login_success']:
            info('login successful!')
            return login_data['user'], codecs.encode(pickle.dumps(list(cookies)), "base64").decode()
        else:
            error('login failed, verify your username/password and try again.')

    def authenticated_request(self, url, args=None, byte_range=None, retries=HTTP_RETRY_COUNT, delay=HTTP_FETCH_DELAY):
        return request(url, args, byte_range, retries, delay, self.cookies)

    def get_database_cursor(self) -> pymongo.cursor:
        return self.game_collection.find({'game_source': 'GOG', 'owners': {'$elemMatch': {'user': self.user}}})

    def get_game_by_id(self, game_id):
        return self.game_collection.find_one({'id': game_id})

    def upsert_game(self, id, game):
        return self.game_collection.update_one({'game_source': 'GOG', 'id': id}, {'$set': game}, upsert=True)

    def handle_game_updates(self, olditem, newitem):
        if newitem.has_updates:
            info('  -> gog flagged this game as updated')

        if olditem['title'] != newitem.title:
            info('  -> title has changed "{}" -> "{}"'.format(olditem['title'], newitem.title))
            # TODO: rename the game directory

        if olditem['long_title'] != newitem.long_title:
            try:
                info('  -> long title has change "{}" -> "{}"'.format(olditem['long_title'], newitem.long_title))
            except UnicodeEncodeError:
                pass

        if olditem['changelog'] != newitem.changelog and newitem.changelog not in [None, '']:
            info('  -> changelog was updated')

        if olditem['owners'] != newitem.owners:
            info('  -> owner/serial changed from {} to {}'.format(str(olditem['owners']), str(newitem.owners)))

    def fetch_file_info(self, d, fetch_md5):
        # fetch file name/size
        with self.authenticated_request(d.href, byte_range=(0, 0)) as page:
            d.name = unquote(urlparse(page.geturl()).path.split('/')[-1])
            d.size = int(page.headers['Content-Range'].split('/')[-1])

            # fetch file md5
            if fetch_md5:
                if os.path.splitext(page.geturl())[1].lower() not in SKIP_MD5_FILE_EXT:
                    tmp_md5_url = page.geturl().replace('?', '.xml?')
                    try:
                        with request(tmp_md5_url) as page:
                            shelf_etree = xml.etree.ElementTree.parse(page).getroot()
                            d.md5 = shelf_etree.attrib['md5']
                    except HTTPError as e:
                        if e.code == 404:
                            warn("no md5 data found for {}".format(d.name))
                        else:
                            raise
                    except xml.etree.ElementTree.ParseError:
                        warn('xml parsing error occurred trying to get md5 data for {}'.format(d.name))

    def filter_downloads(self, out_list, downloads_list, lang_list, os_list):
        """filters any downloads information against matching lang and os, translates
        them, and extends them into out_list
        """
        filtered_downloads = []
        downloads_dict = dict(downloads_list)

        # hold list of valid languages languages as known by gogapi json stuff
        valid_langs = []
        for lang in lang_list:
            valid_langs.append(LANG_TABLE[lang])

        # check if lang/os combo passes the specified filter
        for lang in downloads_dict:
            if lang in valid_langs:
                for os_type in downloads_dict[lang]:
                    if os_type in os_list:
                        for download in downloads_dict[lang][os_type]:
                            # passed the filter, create the entry
                            d = AttrDict(desc=download['name'],
                                         os_type=os_type,
                                         lang=lang,
                                         version=download['version'],
                                         href=GOG_HOME_URL + download['manualUrl'],
                                         md5=None,
                                         name=None,
                                         size=None
                                         )
                            try:
                                self.fetch_file_info(d, True)
                            except HTTPError:
                                warn("failed to fetch %s" % d.href)
                            filtered_downloads.append(d)

        out_list.extend(filtered_downloads)

    def filter_extras(self, out_list, extras_list):
        """filters and translates extras information and adds them into out_list
        """
        filtered_extras = []

        for extra in extras_list:
            d = AttrDict(desc=extra['name'],
                         os_type='extra',
                         lang='',
                         version=None,
                         href=GOG_HOME_URL + extra['manualUrl'],
                         md5=None,
                         name=None,
                         size=None,
                         )
            try:
                self.fetch_file_info(d, False)
            except HTTPError:
                warn("failed to fetch %s" % d.href)
            filtered_extras.append(d)

        out_list.extend(filtered_extras)

    def filter_dlcs(self, item, dlc_list, lang_list, os_list):
        """filters any downloads/extras information against matching lang and os, translates
        them, and adds them to the item downloads/extras
        dlcs can contain dlcs in a recursive fashion, and oddly GOG does do this for some titles.
        """
        for dlc_dict in dlc_list:
            self.filter_downloads(item.downloads, dlc_dict['downloads'], lang_list, os_list)
            self.filter_extras(item.extras, dlc_dict['extras'])
            self.filter_dlcs(item, dlc_dict['dlcs'], lang_list, os_list)  # recursive

    def update_database(self, os_list, lang_list, skipknown=False, updateonly=False, id=None):
        media_type = GOG_MEDIA_TYPE_GAME
        items = []
        known_ids = []
        i = 0

        api_url = GOG_ACCOUNT_URL
        api_url += "/getFilteredProducts"

        # Make convenient list of known ids
        if skipknown:
            for item in self.get_database_cursor():
                known_ids.append(item.id)

        # Fetch shelf data
        done = False
        while not done:
            i += 1  # starts at page 1
            if i == 1:
                info('fetching game product data (page %d)...' % i)
            else:
                info('fetching game product data (page %d / %d)...' % (i, json_data['totalPages']))

            url = api_url + "?" + urlencode({'mediaType': media_type,
                                             'sortBy': 'title',
                                             'page': str(i)})

            with self.authenticated_request(url, delay=0) as data_request:
                reader = codecs.getreader("utf-8")
                try:
                    json_data = json.load(reader(data_request))
                except ValueError:
                    error('failed to load product data (are you still logged in?)')
                    return 1

                # Parse out the interesting fields and add to items dict
                for item_json_data in json_data['products']:
                    # skip games marked as hidden
                    if item_json_data.get('isHidden', False) is True:
                        continue

                    item = AttrDict(game_source='GOG')
                    item.id = item_json_data['id']
                    item.title = item_json_data['slug']
                    item.long_title = item_json_data['title']
                    item.genre = item_json_data['category']
                    item.image_url = item_json_data['image']
                    item.store_url = item_json_data['url']
                    item.media_type = media_type
                    item.rating = item_json_data['rating']
                    item.has_updates = bool(item_json_data['updates']) or bool(item_json_data['isNew'])

                    if id:
                        if item.title == id or str(item.id) == id:  # support by game title or gog id
                            info('found "{}" in product data!'.format(item.title))
                            items.append(item)
                            done = True
                    elif updateonly:
                        if item.has_updates:
                            items.append(item)
                    elif skipknown:
                        if item.id not in known_ids:
                            items.append(item)
                    else:
                        items.append(item)

                if i >= json_data['totalPages']:
                    done = True

        # bail if there's nothing to do
        if len(items) == 0:
            if id:
                warn('game id "{}" was not found in your product data'.format(id))
            elif updateonly:
                warn('no new game updates found.')
            elif skipknown:
                warn('no new games found.')
            else:
                warn('nothing to do')
            return

        items_count = len(items)
        print_padding = len(str(items_count))
        if not id and not updateonly and not skipknown:
            info('found %d games !!%s' % (items_count, '!' * int(items_count / 100)))  # teehee

        # fetch item details
        i = 0
        for item in sorted(items, key=lambda item: item.title):
            api_url = GOG_ACCOUNT_URL
            api_url += "/gameDetails/{}.json".format(item.id)

            i += 1
            info("(%*d / %d) fetching game details for %s..." % (print_padding, i, items_count, item.title))

            try:
                with self.authenticated_request(api_url) as data_request:
                    reader = codecs.getreader("utf-8")
                    item_json_data = json.load(reader(data_request))
                    item.bg_url = item_json_data['backgroundImage']
                    owner = {'user': self.user}
                    serial = item_json_data['cdKey']
                    if serial:
                        owner['serial'] = serial
                    item.owners = [owner]
                    item.forum_url = item_json_data['forumLink']
                    item.changelog = item_json_data['changelog']
                    item.release_timestamp = item_json_data['releaseTimestamp']
                    item.gog_messages = item_json_data['messages']
                    item.downloads = []
                    item.extras = []

                    # parse json data for downloads/extras/dlcs
                    self.filter_downloads(item.downloads, item_json_data['downloads'], lang_list, os_list)
                    self.filter_extras(item.extras, item_json_data['extras'])
                    self.filter_dlcs(item, item_json_data['dlcs'], lang_list, os_list)

                    # update gamesdb with new item
                    game = self.get_game_by_id(item.id)
                    if game is not None:
                        item.owners = [o for o in game['owners'] if str(o['user']) != str(self.user)] + item.owners
                        self.handle_game_updates(game, item)
                    game = item
                    self.upsert_game(item.id, game)

            except Exception:
                log_exception('error')
        return 0

    def download(self, savedir, groupos=True, skipextras=False, skipgames=False, skipids=None, dryrun=False, id=None):
        sizes, rates, errors = {}, {}, {}
        work = Queue()  # build a list of work items

        games = self.get_database_cursor()
        items = list(games)
        work_dict = dict()

        # util
        def megs(b):
            return '%.1fMB' % (b / float(1024 ** 2))

        def gigs(b):
            return '%.2fGB' % (b / float(1024 ** 3))

        def dest_file_path(dir, os_type, file):
            if not groupos:
                return os.path.join(dir, file)
            else:
                osdir = os.path.join(dir, os_type)
                if not dryrun:
                    if not os.path.isdir(osdir):
                        os.makedirs(osdir)
                return os.path.join(osdir, file)

        if id:
            id_found = False
            for item in items:
                if item['title'] == id:
                    items = [item]
                    id_found = True
                    break
            if not id_found:
                error('no game with id "{}" was found.'.format(id))
                exit(1)

        if skipids:
            info("skipping games with id[s]: {%s}" % skipids)
            ignore_list = skipids.split(",")
            items[:] = [item for item in items if item['title'] not in ignore_list]

        # Find all items to be downloaded and push into work queue
        for item in sorted(items, key=lambda g: g['title']):
            info("{%s}" % item['title'])
            item_homedir = os.path.join(savedir, item['title'])
            if not dryrun:
                if not os.path.isdir(item_homedir):
                    os.makedirs(item_homedir)

            if skipextras:
                item['extras'] = []

            if skipgames:
                item['downloads'] = []

            # Populate queue with all files to be downloaded
            for game_item in item['downloads'] + item['extras']:
                if game_item['name'] is None:
                    continue  # no game name, usually due to 404 during file fetch
                dest_file = dest_file_path(item_homedir, game_item['os_type'], game_item['name'])

                if os.path.isfile(dest_file):
                    if game_item['size'] is None:
                        warn('     unknown    %s has no size info.  skipping')
                        continue
                    elif game_item['size'] != os.path.getsize(dest_file):
                        warn('     fail       %s has incorrect size.' % game_item['name'])
                    else:
                        info('     pass       %s' % game_item['name'])
                        continue  # move on to next game item

                info('     download   %s' % game_item['name'])
                sizes[dest_file] = game_item['size']

                work_dict[dest_file] = (game_item['href'], game_item['size'], 0, game_item['size'] - 1, dest_file)

        for work_item in work_dict:
            work.put(work_dict[work_item])

        if dryrun:
            info("{} left to download".format(gigs(sum(sizes.values()))))
            return  # bail, as below just kicks off the actual downloading

        info('-' * 60)

        # work item I/O loop
        def ioloop(tid, path, page, out):
            sz, t0 = True, time.time()
            while sz:
                buf = page.read(4 * 1024)
                t = time.time()
                out.write(buf)
                sz, dt, t0 = len(buf), t - t0, t
                with lock:
                    sizes[path] -= sz
                    rates.setdefault(path, []).append((tid, (sz, dt)))

        # downloader worker thread main loop
        def worker():
            tid = threading.current_thread().ident
            while not work.empty():
                (href, sz, start, end, path) = work.get()
                try:
                    dest_dir = os.path.dirname(path)
                    with lock:
                        if not os.path.isdir(dest_dir):
                            os.makedirs(dest_dir)
                        if os.path.exists(path) and os.path.getsize(
                                path) > sz:  # if needed, truncate file if ours is larger than expected size
                            with open_notrunc(path) as f:
                                f.truncate(sz)
                    with open_notrunc(path) as out:
                        out.seek(start)
                        se = start, end
                        try:
                            with self.authenticated_request(href, byte_range=se) as page:
                                hdr = page.headers['Content-Range'].split()[-1]
                                if hdr != '%d-%d/%d' % (start, end, sz):
                                    with lock:
                                        error("chunk request has unexpected Content-Range. "
                                              "expected '%d-%d/%d' received '%s'. skipping."
                                              % (start, end, sz, hdr))
                                else:
                                    assert out.tell() == start
                                    ioloop(tid, path, page, out)
                                    assert out.tell() == end + 1
                        except HTTPError as e:
                            error("failed to download %s, byte_range=%s" % (os.path.basename(path), str(se)))
                except IOError as e:
                    with lock:
                        print('!', path, file=sys.stderr)
                        errors.setdefault(path, []).append(e)
                work.task_done()

        # detailed progress report
        def progress():
            with lock:
                left = sum(sizes.values())
                for path, flowrates in sorted(rates.items()):
                    flows = {}
                    for tid, (sz, t) in flowrates:
                        szs, ts = flows.get(tid, (0, 0))
                        flows[tid] = sz + szs, t + ts
                    bps = sum(szs / ts for szs, ts in list(flows.values()) if ts > 0)
                    info('%10s %8.1fMB/s %2dx  %s' % \
                         (megs(sizes[path]), bps / 1024.0 ** 2, len(flows),
                          "%s/%s" % (os.path.basename(os.path.split(path)[0]), os.path.split(path)[1])))
                if len(rates) != 0:  # only update if there's change
                    info('%s remaining' % gigs(left))
                rates.clear()

        # process work items with a thread pool
        lock = threading.Lock()
        pool = []
        for i in range(HTTP_GAME_DOWNLOADER_THREADS):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            pool.append(t)
        try:
            while any(t.is_alive() for t in pool):
                progress()
                time.sleep(1)
        except KeyboardInterrupt:
            raise
        except:
            with lock:
                log_exception('')
            raise


