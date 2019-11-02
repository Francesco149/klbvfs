#!/bin/env python3

# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.

import apsw
import os.path
import sys
from bs4 import BeautifulSoup
import urllib.parse
import base64
import hmac
import hashlib
import struct


def i8(x):
  return x & 0xFF


def i32(x):
  return x & 0xFFFFFFFF


def hmac_sha1(key, s):
  hmacsha1 = hmac.new(key, digestmod=hashlib.sha1)
  hmacsha1.update(s)
  return hmacsha1.digest()


class KLBVFS(apsw.VFS):
  def __init__(self, vfsname='klb_vfs', basevfs=''):
    self.vfsname = vfsname
    self.basevfs = basevfs
    apsw.VFS.__init__(self, self.vfsname, self.basevfs)

  def xOpen(self, name, flags):
    return KLBVFSFile(self.basevfs, name, flags)

  def xAccess(self, pathname, flags):
    actual_path = pathname.split(' ', 2)[1]
    return super(KLBVFS, self).xAccess(actual_path, flags)

  def xFullPathname(self, name):
    split = name.split(' ', 2)
    fullpath = super(KLBVFS, self).xFullPathname(split[1])
    return split[0] + ' ' + fullpath


class KLBVFSFile(apsw.VFSFile):
  def __init__(self, inheritfromvfsname, filename, flags):
    split = filename.filename().split(' ', 2)
    keysplit = split[0].split('.')
    self.key = [int(x) for x in keysplit]
    apsw.VFSFile.__init__(self, inheritfromvfsname, split[1], flags)

  def xRead(self, amount, offset):
    result = super(KLBVFSFile, self).xRead(amount, offset)
    random2 = 0x000343fd
    random1 = 0x00269ec3
    key1 = self.key[0]
    if offset == 0:
      random1 = 0
      random2 = self.key[1]
      random_multiplier = self.key[2]
      rand_seed = 1
    else:
      random_multiplier = 1
      rand_seed = 0
      tmpoff = offset
      while tmpoff != 0:
        if (tmpoff & 1) != 0:
          rand_seed = i32(i32(random_multiplier * random1) + rand_seed)
          random_multiplier = i32(random_multiplier * random2)
        tmpoff >>= 1
        random1 = i32(i32(random2 * random1) + random1)
        random2 = i32(random2 * random2)
      random1 = 1
      random3 = 0x00269ec3
      key1 = i32(i32(random_multiplier * key1) + rand_seed)
      random2 = 0
      rand_seed = 0x000343fd
      tmpoff = offset
      while tmpoff != 0:
        if (tmpoff & 1) != 0:
          random2 = i32(i32(random1 * random3) + random2)
          random1 = i32(random1 * rand_seed)
        tmpoff >>= 1
        random3 = i32(i32(rand_seed * random3) + random3)
        rand_seed = i32(rand_seed * rand_seed)
      random2 = i32(i32(random1 * self.key[1]) + random2)
      random_multiplier = self.key[2]
      rand_seed = 1
      random1 = 0
      random3 = 0x00269ec3
      random4 = 0x000343fd
      tmpoff = offset
      while tmpoff != 0:
        if (tmpoff & 1) != 0:
          random1 = i32(i32(rand_seed * random3) + random1)
          rand_seed = i32(rand_seed * random4)
        tmpoff >>= 1
        random3 = i32(i32(random4 * random3) + random3)
        random4 = i32(random4 * random4)
    random1 = i32(i32(rand_seed * random_multiplier) + random1)
    b = bytearray(result)
    for i in range(amount):
      b[i] ^= i8(random2 >> 24) ^ i8(key1 >> 24) ^ i8(random1 >> 24)
      key1 = i32(i32(key1 * 0x000343fd) + 0x00269ec3)
      random1 = i32(i32(random1 * 0x000343fd) + 0x00269ec3)
      random2 = i32(i32(random2 * 0x000343fd) + 0x00269ec3)
    return bytes(b)


def sqlite_key(dbfile):
  abspath = os.path.abspath(dbfile)
  base = os.path.dirname(abspath)
  base = os.path.dirname(base)
  base = os.path.dirname(base)
  pkgname = os.path.basename(base)
  prefs_path = 'shared_prefs/' + pkgname + '.v2.playerprefs.xml'
  prefs = os.path.join(base, prefs_path)
  xml = open(prefs, 'r').read()
  soup = BeautifulSoup(xml, 'lxml-xml')
  sq = urllib.parse.unquote(soup.find('string', {'name': 'SQ'}).getText())
  sq = base64.b64decode(sq)
  basename = os.path.basename(dbfile)
  sha1 = hmac_sha1(key=sq, s=basename.encode('utf-8'))
  return list(struct.unpack('>III', sha1[:12]))


def vpath(path, key):
  return '.'.join([str(i32(x)) for x in key]) + ' ' + path


if __name__ == "__main__":
  vfs = KLBVFS()
  if len(sys.argv) != 3:
    print('usage: ' + sys.argv[0] + ' file.db "sql query"')
    sys.exit(1)
  f = sys.argv[1]
  cmd = sys.argv[2]
  key = sqlite_key(f)
  vp = vpath(path=f, key=key)
  db = apsw.Connection(vp, flags=apsw.SQLITE_OPEN_READONLY, vfs='klb_vfs')
  for row in db.cursor().execute(cmd):
    print(row)
