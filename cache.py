import os
from os import path
from urllib.parse import urlparse
from hashlib import md5

from util import eprint

CACHE_DIR = "cache"
ENC = "utf-8"

def _digest(string):
    return md5(bytes(string, ENC)).hexdigest()

def _getpath(url):
    '''
    Given a full URL (e.g. https://example.com/index.html?v=69),
    return a tuple of its cache item's subdirectory and filename (e.g.
    ("example.com", "871987be283ff15b9a1101c72abcc81d"))
    '''
    u = urlparse(url)
    dirname = u.netloc
    filename = _digest(u.path + ";" + u.params + "?" + u.query)
    return (dirname, filename)

def _open(url, field="file", mode="rb"):
    return open(path.join(CACHE_DIR, *_getpath(url), field), mode)

def createdir():
    '''Create the cache directory if it doesn't exist'''
    try:
        os.makedirs(CACHE_DIR, exist_ok=False)
        eprint(f"Created cache directory at '{CACHE_DIR}'.")
    except FileExistsError:
        eprint(f"Using existing cache directory at '{CACHE_DIR}'.")

def create_entry(url):
    '''
    Create the entry for the resource in the cache directory structure if it
    doesn't already exist.
    Returns `True` if the entry already exists, `False` otherwise.
    '''
    try:
        os.makedirs(path.join(CACHE_DIR, *_getpath(url)), exist_ok=False)
        return True
    except FileExistsError:
        return False

def get_date(url):
    '''
    Returns the date in seconds associated with the cache item if it exists,
    None otherwise.
    Use this function to determine existence and freshness of cache items.
    '''
    try:
        with _open(url, "date", "r") as f:
            s = f.readline().strip()
            return int(s)
    except FileNotFoundError:
        return None

def set_date(url, date: int):
    with _open(url, "date", "w") as f:
        f.write(str(date))

def get_file(url):
    with _open(url, "file", "rb") as f:
        return f.read()

def set_file(url, filedata: bytes):
    with _open(url, "file", "wb") as f:
        f.write(filedata)

def open_file(url, mode="rb"):
    """
    Returns the file corresponding to the provided resource URL.
    Assumes the cache entry has already been created using `create_entry(url)`.
    """
    return _open(url, "file", mode)
