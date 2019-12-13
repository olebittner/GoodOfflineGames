# GoodOfflineGames

Command line tool to download your drm-free game collection for full offline access.

It provides support for multiple accounts and is easily expandable to
add more content and authentication providers.

GoodOfflineGames is written in Python 3 and uses MongoDB for metadata storage.

## Quick Start
Make sure you have `Python 3` and `pip` installed. You also need a running
`MongoDB` server. [You can read how to install and setup a MongoDB here.](https://docs.mongodb.com/manual/administration/install-community/)

This example use case configures the tool to download games from one GOG
account. If you want to download games from another provider simply 
replace `GOG` with the provider of your choice.
You can repeat the first command to setup multiple users and/or 
providers
```bash
# Clone this git and enter the directory
$ git clone https://github.com/olebittner/GoodOfflineGames.git
$ cd GoodOfflineGames

# Install required Python packages using pip
$ pip install -r requirements.txt

# Login to Content Provider
$ GoodOfflineGames.py login add File GOG

# Fetch game data
$ GoodOfflineGames.py update

# Download all games
$ GoodOfflineGames.py download /path/to/store/downloads
```
## Content Provider Integrations

- `✔` fully functional
- `⚠` partially functional
- `🍪` login requires extracting a session cookie from a browser
- `📦` integration is included by default
- `⬜` planned or WIP 

| Provider          | Games | Extras                            | Login  | Link         |
|-------------------|-------|-----------------------------------|--------|--------------|
| [GOG]             | ✔     | ✔                                 | ✔     | [📦][iGOG]     |
| [HumbleBundle]    | ✔     | ⚠ Only when bundled with game     | 🍪     | [📦][iHB]      |

[GOG]: https://www.gog.com/
[HumbleBundle]: https://www.humblebundle.com/

[iGOG]: sources/GOG.py
[iHB]: sources/HumbleBundle.py
## Usage
**General**
```
usage: GoodOfflineGames.py [-h] [--db DB] {login,update,download} ...

optional arguments:
  -h, --help            show this help message and exit
  --db DB, --database DB
                        Specify a MongoDB using a Connection String

Commands:
  {login,update,download}
    login               Login to one of the game sources
    update              Update game database
    download            Download games listed in the database
```
**Login**
```
usage: GoodOfflineGames.py login [-h] {add,remove} auth content

positional arguments:
  {add,remove}
  auth          specify the authentication provider to store the credentials
  content       specify the content provider to authenticate

optional arguments:
  -h, --help    show this help message and exit
```
**Update**
```
usage: GoodOfflineGames.py update [-h] [-c CONTENT [CONTENT ...]]
                                  [-a AUTH [AUTH ...]] [-u USER [USER ...]]

optional arguments:
  -h, --help            show this help message and exit
  -c CONTENT [CONTENT ...], --content CONTENT [CONTENT ...]
                        specify one or more content providers
  -a AUTH [AUTH ...], --auth AUTH [AUTH ...]
                        specify one or more authentication providers
  -u USER [USER ...], --user USER [USER ...]
                        specify one or more users
```
**Download**
```
usage: GoodOfflineGames.py download [-h] [-p PATH] [-c CONTENT [CONTENT ...]]
                                    [-a AUTH [AUTH ...]] [-u USER [USER ...]]

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  Destination directory for downloads
  -c CONTENT [CONTENT ...], --content CONTENT [CONTENT ...]
                        specify one or more content providers
  -a AUTH [AUTH ...], --auth AUTH [AUTH ...]
                        specify one or more authentication providers
  -u USER [USER ...], --user USER [USER ...]
                        specify one or more users
```

## Credit
The idea for this tool was inspired by [Eddies gogrepo](https://github.com/eddie3/gogrepo).
In fact the GOG integration for this tool is a modified version his script.

## License
[GPLv3+](./LICENSE)