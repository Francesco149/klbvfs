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
import re
import multiprocessing as mp


def i8(x):
  return x & 0xFF


def i32(x):
  return x & 0xFFFFFFFF


def hmac_sha1(key, s):
  hmacsha1 = hmac.new(key, digestmod=hashlib.sha1)
  hmacsha1.update(s)
  return hmacsha1.digest()


def klbvfs_transform_byte(byte, key):
  byte ^= i8(key[0] >> 24) ^ i8(key[1] >> 24) ^ i8(key[2] >> 24)
  key[0] = i32(i32(key[0] * 0x343fd) + 0x269ec3)
  key[1] = i32(i32(key[1] * 0x343fd) + 0x269ec3)
  key[2] = i32(i32(key[2] * 0x343fd) + 0x269ec3)
  return byte


# this is used for random seeks through encrypted files
# it computes the prng state in log(offset) instead of offset cycles
# https://www.nayuki.io/page/fast-skipping-in-a-linear-congruential-generator
def prng_seek(k, offset, mul, add, mod):
  mul1 = mul - 1
  modmul = mul1 * mod
  y = (pow(mul, offset, modmul) - 1) // mul1 * add
  z = pow(mul, offset, mod) * k
  return (y + z) % mod


def klbvfs_transform(data, key):
  return bytes([klbvfs_transform_byte(x, key) for x in data]), len(data)


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
    encrypted = super(KLBVFSFile, self).xRead(amount, offset)
    k = [prng_seek(k, offset, 0x343fd, 0x269ec3, 2**32) for k in self.key]
    res, _ = klbvfs_transform(bytearray(encrypted), k)
    return res


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


def decrypt_db(source):
  dstpath = '_'.join(source.split('_')[:-1])
  key = sqlite_key(source)
  src = codecs.open(source, mode='rb', encoding='klbvfs', errors=key)
  dst = open(dstpath, 'wb+')
  print('%s -> %s' % (source, dstpath))
  shutil.copyfileobj(src, dst)
  src.close()
  dst.close()
  return dstpath


def do_decrypt(args):
  for source in args.files:
    decrypt_db(source)


def decrypt_worker(source, pack_name, head, size, key1, key2):
  dstdir = os.path.join(source, 'texture')
  fpath = os.path.join(dstdir, "%s_%d.png" % (pack_name, head))
  print("[decrypting] " + fpath)
  pkgpath = os.path.join(source, "pkg" + pack_name[:1], pack_name)
  key = [key1, key2, 0x3039]
  pkg = codecs.open(pkgpath, mode='rb', encoding='klbvfs', errors=key)
  pkg.seek(head)
  dst = open(fpath, 'wb+')
  shutil.copyfileobj(pkg, dst, size)
  return fpath


def do_dump(args):
  for source in args.directories:
    pattern = re.compile("asset_a_ja_0.db_[a-z0-9]+.db")
    matches = [f for f in os.listdir(source) if pattern.match(f)]
    dbpath = os.path.join(source, matches[0])
    dstdir = os.path.join(source, 'texture')
    try:
      os.mkdir(dstdir)
    except FileExistsError:
      pass
    db = klb_sqlite(dbpath).cursor()
    sel = 'select distinct pack_name, head, size, key1, key2 from texture'
    with mp.Pool() as p:
      results = []
      f = decrypt_worker
      for (pack_name, head, size, key1, key2) in db.execute(sel):
        r = p.apply_async(f, (source, pack_name, head, size, key1, key2))
        results.append(r)
      for r in results:
        print("[done] " + r.get())


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
  decrypt.add_argument('files', nargs='+')
  decrypt.set_defaults(func=do_decrypt)
  desc = 'dump encrypted assets from pkg files'
  dump = sub.add_parser('dump', aliases=['d'], help=desc)
  desc = 'directory where the pkg* folders and db files are located. '
  desc += 'usually /data/data/com.klab.lovelive.allstars/files/files'
  dump.add_argument('directories', nargs='?', help=desc, default='.')
  dump.set_defaults(func=do_dump)
  args = parser.parse_args(sys.argv[1:])
  if 'func' not in args:
    parser.parse_args(['-h'])
  args.func(args)
