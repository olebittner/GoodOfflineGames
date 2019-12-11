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

import itertools
import json
import logging
import os
import sys
import threading
import time
from http import cookiejar
from os.path import basename
from queue import Queue
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse, urljoin, urlsplit
from urllib.request import HTTPCookieProcessor, build_opener, Request
from lxml import etree

import pymongo

info = logging.info
warn = logging.warning
debug = logging.debug
error = logging.error
log_exception = logging.exception

needs_authentication = True

HB_HOME_URL = "https://www.humblebundle.com"
HB_LOGIN_URL = "https://www.humblebundle.com/login"
HB_LIBRARY_URL = "/home/library"
HB_API_ORDER = "/api/v1/order/%s"

# HTTP request settings
HTTP_FETCH_DELAY = 0  # in seconds
HTTP_RETRY_DELAY = 5  # in seconds
HTTP_RETRY_COUNT = 3
HTTP_GAME_DOWNLOADER_THREADS = 4
HTTP_PERM_ERRORCODES = (404, 403, 503)

VALID_PLATFORM_TYPES = ['windows', 'linux', 'mac', 'android', 'audio', 'ebook', 'video']
EXTRAS_PLATFORM_TYPES = ['audio', 'ebook', 'video']


def get_session_cookie(auth):
    return cookiejar.Cookie(name='_simpleauth_sess',
                            value=auth,
                            domain=urlsplit(HB_HOME_URL)[1],
                            path='/',
                            expires=63072000 + int(auth.split('|')[1]),  # 63072000 equals 1. January 1972 00:00:00
                            secure=True,
                            version=0,
                            domain_specified=False,
                            domain_initial_dot=False,
                            path_specified=False,
                            port=None,
                            port_specified=False,
                            discard=False,
                            comment=None,
                            comment_url=None,
                            rest={}, )


def request(url, args=None, cookies=cookiejar.CookieJar()):
    cookieproc = HTTPCookieProcessor(cookies)
    opener = build_opener(cookieproc)
    url = urljoin(HB_HOME_URL, url)
    if args is not None:
        enc_args = urlencode(args)
        enc_args = enc_args.encode('ascii')  # needed for Python 3
    else:
        enc_args = None
    req = Request(url, data=enc_args)
    return opener.open(req)


class HumbleBundle:

    def __init__(self, collection: pymongo.collection, user, auth_blob) -> None:
        self.game_collection: pymongo.collection = collection
        self.user = user
        self.cookies = self.recreate_cookiejar(auth_blob)
        super().__init__()

    @staticmethod
    def recreate_cookiejar(cookie):
        jar = cookiejar.CookieJar()
        jar.set_cookie(get_session_cookie(cookie))
        return jar

    def __request(self, url, args=None, retries=HTTP_RETRY_COUNT, delay=HTTP_FETCH_DELAY, ):
        time.sleep(delay)
        req = request(url, args, self.cookies)
        if req.code is 200:
            if url not in req.url:
                error('Request failed (are you still logged in?)')
                raise
            return req
        elif req.code in HTTP_PERM_ERRORCODES:
            warn('request failed: %s.  will not retry.', req.code)
            raise
        else:
            if retries > 0:
                warn('request failed: %s (%d retries left) -- will retry in %ds...' % (
                req.code, retries, HTTP_RETRY_DELAY))
                return self.__request(url=url, args=args, retries=retries - 1, delay=HTTP_RETRY_DELAY)

    def __get_game_by_machine_name(self, machine_name):
        return self.game_collection.find_one({'machine_name': machine_name})

    def __upsert_game(self, machine_name, game):
        return self.game_collection.update_one({'game_source': 'HB', 'machine_name': machine_name}, {'$set': game},
                                               upsert=True)

    def __get_database_cursor(self) -> pymongo.cursor:
        return self.game_collection.find({'game_source': 'HB', 'owners': {'$elemMatch': {'user': self.user}}})

    def update_database(self, os_list, lang_list, skipknown=False, updateonly=False, id=None):
        home = self.__request(HB_LIBRARY_URL)
        html = etree.HTML(home.read().decode('utf-8'))
        key_elements = html.xpath("//script[@id = '%s']" % 'user-home-json-data')
        purchases = list(itertools.chain(*[json.loads(element.text)['gamekeys'] for element in key_elements]))
        items_count = len(purchases)
        print_padding = len(str(items_count))
        if items_count == 0:
            warn('%s owns no games!' % self.user)
            return 1
        for i, purchase_key in enumerate(purchases):
            info("(%*d / %d) fetching details for purchase %s..." % (print_padding, i+1, items_count, purchase_key))
            with self.__request(HB_API_ORDER % purchase_key) as purchase_request:
                purchase = json.loads(purchase_request.read().decode('utf-8'))
                info("%s %s" % (' ' * (35 + print_padding*2), purchase['product']['machine_name']))
                product = {'category': purchase['product']['category'],
                           'machine_name': purchase['product']['machine_name'],
                           'human_name': purchase['product']['human_name'],
                           'gamekey': purchase['gamekey'],
                           'created': purchase['created']}

                subproducts = purchase['subproducts']
                if len(subproducts) < 1:
                    info("    %s contains no downloads: skipping!" % product['machine_name'])
                for subproduct in subproducts:
                    name = subproduct['machine_name']
                    downloads, extras = self.__filter_downloads(subproduct['downloads'], os_list)
                    if len(downloads) < 1:
                        info("    no matching downloads for %s" % name)
                        continue
                    item = {'game_source': 'HB',
                            'machine_name': name,
                            'url': subproduct['url'],
                            'library_family_name': subproduct['library_family_name'],
                            'human_name': subproduct['human_name'],
                            'icon': subproduct['icon'],
                            'owners': [],
                            'downloads': downloads,
                            'extras': extras}

                    game = self.__get_game_by_machine_name(name)
                    owner_set = False
                    if not game:
                        info("    adding game   %s..." % name)
                    else:
                        info("    updating game %s..." % name)
                        # TODO Handle Update
                        item['owners'] = game['owners']
                        for owner in item['owners']:
                            if owner['user'] == self.user:
                                if product not in owner['purchases']:
                                    owner['purchases'].append(product)
                                owner_set = True
                    if not owner_set:
                        item['owners'].append({'user': self.user, 'purchases': [product]})

                    self.__upsert_game(name, item)
        return 0

    def download(self, savedir, groupos=True, skipextras=False, skipgames=False, skipids=None, dryrun=False, id=None):
        links = {}

        sizes, rates, errors = {}, {}, {}
        work = Queue()  # build a list of work items

        games = self.__get_database_cursor()
        items = list(games)
        work_dict = dict()

        def get_download_link(game_download, download_struct, purchase_keys):
            id = game_download + download_struct
            if id in links:
                return links[id]
            else:
                for key in purchase_keys:
                    with self.__request(HB_API_ORDER % key) as purchase_request:
                        purchase = json.loads(purchase_request.read().decode('utf-8'))
                        for product in purchase['subproducts']:
                            for download in product['downloads']:
                                for struct in download['download_struct']:
                                    if 'url' in struct and 'web' in struct['url']:
                                        links[download['machine_name'] + struct['name']] = struct['url']['web']
            if id in links:
                return links[id]
            else:
                raise

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
                        pass  # os.makedirs(osdir)
                return os.path.join(osdir, file)

        def open_notrunc(name, bufsize=4 * 1024):
            flags = os.O_WRONLY | os.O_CREAT
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY  # windows
            fd = os.open(name, flags, 0o666)
            return os.fdopen(fd, 'wb', bufsize)

        if id:
            id_found = False
            for item in items:
                if item['machine_name'] == id:
                    items = [item]
                    id_found = True
                    break
            if not id_found:
                error('no game with id "{}" was found.'.format(id))
                exit(1)

        if skipids:
            info("skipping games with id[s]: {%s}" % skipids)
            ignore_list = skipids.split(",")
            items[:] = [item for item in items if item['machine_name'] not in ignore_list]

        # Find all items to be downloaded and push into work queue
        for item in sorted(items, key=lambda g: g['machine_name']):
            info("{%s}" % item['machine_name'])
            item_homedir = os.path.join(savedir, item['machine_name'])
            purchases = [owner['purchases'] for owner in item['owners'] if owner['user'] == self.user][0]
            purchase_keys = [purchase['gamekey'] for purchase in purchases]
            if not dryrun:
                if not os.path.isdir(item_homedir):
                    pass  # os.makedirs(item_homedir)

            if skipextras:
                item['extras'] = []

            if skipgames:
                item['downloads'] = []

            # Populate queue with all files to be downloaded
            for game_item in item['downloads'] + item['extras']:
                for download_struct in game_item['download_struct']:
                    if not download_struct:
                        continue
                    if 'url' not in download_struct or 'web' not in download_struct['url']:
                        continue
                    if game_item['machine_name'] is None:
                        continue  # no game name, usually due to 404 during file fetch
                    href = get_download_link(game_item['machine_name'], download_struct['name'], purchase_keys)
                    file_name = basename(urlparse(href).path)
                    dest_file = dest_file_path(item_homedir, game_item['platform'], file_name)

                    if os.path.isfile(dest_file):
                        if download_struct['file_size'] is None:
                            warn('     unknown    %s has no size info.  skipping' % file_name)
                            continue
                        elif download_struct['file_size'] != os.path.getsize(dest_file):
                            warn('     fail       %s has incorrect size.' % file_name)
                        else:
                            info('     pass       %s' % file_name)
                            continue  # move on to next game item

                    info('     download   %s' % file_name)
                    sizes[dest_file] = download_struct['file_size']

                    work_dict[dest_file] = (href,
                                            download_struct['file_size'], 0, download_struct['file_size'] - 1,
                                            dest_file)

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
                            with request(href) as page:
                                # hdr = page.headers['Content-Range'].split()[-1]
                                assert out.tell() == start
                                ioloop(tid, path, page, out)
                                assert out.tell() == end + 1
                        except (HTTPError, AssertionError) as e:
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

    @staticmethod
    def interactive_login():
        username = input("Username: ")
        print("Open %s in your browser, login and paste the value of the cookie '%s' below." %
              (HB_LOGIN_URL, '_simpleauth_sess'))
        print("Your cookie should look something like:")
        print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
              "|1234567896|XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        session_cookie = input("Session Cookie: ")

        jar = HumbleBundle.recreate_cookiejar(session_cookie)

        test = request(HB_LIBRARY_URL, cookies=jar)
        if test.code is not 200 or urljoin(HB_HOME_URL, HB_LIBRARY_URL) not in test.url:
            error('Login failed!')
            return
        info('Login successful!')

        return username, session_cookie

    def __filter_downloads(self, downloads, os_list):
        filtered_downloads = []
        extras = []

        valid_downloads = []
        for download in downloads:
            for index, download_struct in enumerate(download['download_struct']):
                if 'url' in download_struct:
                    if 'web' in download['download_struct'][index]['url']:
                        url = download['download_struct'][index]['url']['web']
                        download['download_struct'][index]['name_unsafe'] = basename(urlparse(url).path)
                    download['download_struct'][index]['url'] = list(download_struct['url'].keys())
                else:
                    download['download_struct'].remove(download_struct)
            if len(download['download_struct']) > 0:
                valid_downloads.append(download)

        for download in valid_downloads:
            if download['platform'] in os_list:
                filtered_downloads.append(download)

        for download in valid_downloads:
            if download['platform'] in EXTRAS_PLATFORM_TYPES and download not in filtered_downloads:
                extras.append(download)

        return filtered_downloads, extras
