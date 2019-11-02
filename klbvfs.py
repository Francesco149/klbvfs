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
import codecs
import shutil


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


def klb_sqlite(dbfile):
  vfs = KLBVFS()
  key = sqlite_key(dbfile)
  v = vpath(path=dbfile, key=key)
  return apsw.Connection(v, flags=apsw.SQLITE_OPEN_READONLY, vfs='klb_vfs')


def do_query(args):
  for row in klb_sqlite(args.dbfile).cursor().execute(args.sql):
    if len(row) == 1:
      print(row[0])
    else:
      print(row)


def klbvfs_transform_byte(byte, key):
  byte ^= i8(key[1] >> 24) ^ i8(key[0] >> 24) ^ i8(key[2] >> 24)
  key[0] = i32(i32(key[0] * 0x000343fd) + 0x00269ec3)
  key[2] = i32(i32(key[2] * 0x000343fd) + 0x00269ec3)
  key[1] = i32(i32(key[1] * 0x000343fd) + 0x00269ec3)
  return byte


def klbvfs_transform(data, key):
  return bytes([klbvfs_transform_byte(x, key) for x in data]), len(data)


class KLBVFSCodec(codecs.Codec):
  def encode(self, data, key):
    return klbvfs_transform(data, key)

  def decode(self, data, key):
    return klbvfs_transform(data, key)


class KLBVFSStreamReader(KLBVFSCodec, codecs.StreamReader):
  charbuffertype = bytes


class KLBVFSStreamWriter(KLBVFSCodec, codecs.StreamWriter):
  charbuffertype = bytes


def klbvfs_decoder(encoding_name):
  t = klbvfs_transform
  return codecs.CodecInfo(name='klbvfs', encode=t, decode=t,
                          streamreader=KLBVFSStreamReader,
                          streamwriter=KLBVFSStreamWriter,
                          _is_text_encoding=False)


codecs.register(klbvfs_decoder)


def do_decrypt(args):
  key = sqlite_key(args.source)
  src = codecs.open(args.source, mode='rb', encoding='klbvfs', errors=key)
  dst = open(args.destination, 'wb+')
  shutil.copyfileobj(src, dst)


if __name__ == "__main__":
  import argparse
  parser = argparse.ArgumentParser(description='klab sqlite vfs utils')
  sub = parser.add_subparsers()
  desc = 'run a sql query on the encrypted database'
  query = sub.add_parser('query', aliases=['q'], help=desc)
  query.add_argument('dbfile')
  defsql = "select sql from sqlite_master where type='table'"
  query.add_argument('sql', nargs='?', default=defsql)
  query.set_defaults(func=do_query)
  desc = 'clone encrypted database to a regular unencrypted sqlite db'
  decrypt = sub.add_parser('decrypt', aliases=['de'], help=desc)
  decrypt.add_argument('source')
  decrypt.add_argument('destination')
  decrypt.set_defaults(func=do_decrypt)
  args = parser.parse_args(sys.argv[1:])
  if 'func' not in args:
    parser.parse_args(['-h'])
  args.func(args)
