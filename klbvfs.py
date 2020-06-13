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
import magic
import mimetypes
import html


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


def find_db(name, directory):
  pattern = re.compile(name + '.db_[a-z0-9]+.db')
  matches = [f for f in os.listdir(directory) if pattern.match(f)]
  if len(matches) >= 1:
    return os.path.join(directory, matches[0])
  else:
    return None


def dictionary_get(key, directory):
  spl = key.split('.', 2)
  if len(spl) < 2:
    return key
  dbpath = find_db('dictionary_ja_' + spl[0], directory)
  if dbpath is None:
    dbpath = find_db('dictionary_ko_' + spl[0], directory)
    if dbpath is None:
      return key
  db = klb_sqlite(dbpath).cursor()
  sel = 'select message from m_dictionary where id = ?'
  rows = db.execute(sel, (spl[1],))
  res = rows.fetchone()
  if res is None:
    return key
  return html.unescape(res[0])


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


def decrypt_worker(source, table, pack_name, head, size, key1, key2):
  dstdir = os.path.join(source, table)
  fpath = os.path.join(dstdir, "%s_%d" % (pack_name, head))
  pkgpath = os.path.join(source, "pkg" + pack_name[:1], pack_name)
  key = [key1, key2, 0x3039]
  pkg = codecs.open(pkgpath, mode='rb', encoding='klbvfs', errors=key)
  pkg.seek(head)
  buf = pkg.read(1024)
  mime = magic.from_buffer(buf, mime=True)
  ext = mimetypes.guess_extension(mime)
  if mime == 'application/octet-stream':
    if buf.startswith(b'UnityFS'):
      mime = "application/unityfs"
      ext = ".unity3d"
    elif table == 'adv_script':
      # proprietary script format, TODO reverse engineer it
      mime = "application/advscript"
      ext = ".advscript"
  key[0] = key1  # hack: reset rng state, codec has reference to this array
  key[1] = key2
  key[2] = 0x3039
  pkg.seek(head)
  print("[%s] decrypting to %s (%s)" % (fpath, ext, mime))
  with open(fpath + ext, 'wb+') as dst:
    shutil.copyfileobj(pkg, dst, size)
  pkg.close()
  return fpath


def dump_table(dbpath, source, table):
  dstdir = os.path.join(source, table)
  try:
    os.mkdir(dstdir)
  except FileExistsError:
    pass
  db = klb_sqlite(dbpath).cursor()
  sel = 'select distinct pack_name, head, size, key1, key2 from ' + table
  with mp.Pool() as p:
    results = []
    f = decrypt_worker
    for (pack_name, head, size, k1, k2) in db.execute(sel):
      r = p.apply_async(
          f, (source, table, pack_name, head, size, k1, k2))
      results.append(r)
    for r in results:
      print("[%s] done" % r.get())


def do_dump(args):
  for source in args.directories:
    dbpath = find_db('asset_a_ja_0' , source)
    if dbpath is None:
      dbpath = find_db('asset_a_ko' , source)
    for table in args.types:
      dump_table(dbpath, source, table)


def do_dictionary(args):
  for word in args.text:
    print(dictionary_get(word, args.directory))


def do_tickets(args):
  import io
  from PIL import Image, ImageFont, ImageDraw
  import textwrap
  masterdb = klb_sqlite(find_db('masterdata', args.directory)).cursor()
  if find_db('asset_a_ja_0', args.directory) is None:
    db = klb_sqlite(find_db('asset_a_ko', args.directory)).cursor()
    dic = klb_sqlite(find_db('dictionary_ko_k', args.directory)).cursor()
  else:
    db = klb_sqlite(find_db('asset_a_ja_0', args.directory)).cursor()
    dic = klb_sqlite(find_db('dictionary_ja_k', args.directory)).cursor()
  mastersel = '''
  select id, name, description, thumbnail_asset_path
  from m_gacha_ticket
  '''
  i = 0
  pics = []
  for (id, name, desc, asset_path) in masterdb.execute(mastersel):
    sel = '''
    select pack_name, head, size, key1, key2
    from texture
    where asset_path = ?
    '''
    rows = db.execute(sel, (asset_path,))
    pics.append(rows.fetchone() + (id, name, desc))
  img = None
  fnt = None
  fonts = ['NotoSerifCJK-Regular.ttc', 'Arial Unicode.ttf']
  for font in fonts:
    try:
      fnt = ImageFont.truetype(font, 20)
    except OSError:
      continue
    break
  if fnt is None:
    print('warning: falling back to default font')
  for (pakname, head, size, key1, key2, id, name, desc) in pics:
    if fnt is not None:
      name = dictionary_get(name, args.directory)
      desc = dictionary_get(desc, args.directory)
    key = [key1, key2, 0x3039]
    pkgpath = os.path.join(args.directory, "pkg" + pakname[:1], pakname)
    pkg = codecs.open(pkgpath, mode='rb', encoding='klbvfs', errors=key)
    pkg.seek(head)
    imagedata = pkg.read(size)
    mime = magic.from_buffer(imagedata, mime=True)
    ext = mimetypes.guess_extension(mime)
    thumb = Image.open(io.BytesIO(imagedata))
    if img is None:
      (_, height) = thumb.size
      h = int(float(height) * 1.1)
      x = int(float(height) * 0.1)
      img = Image.new('RGBA', (800, x + len(pics) * h), color=(255,) * 3)
      d = ImageDraw.Draw(img)
    y = x + i * h
    img.paste(thumb, (x, y))
    lines = ['%d %s@%d,%d' % (id, pakname, head, size), name]
    print('%d -> "texture/%s_%d%s",' % (id, pakname, head, ext))
    for j, l in enumerate(lines + textwrap.wrap(desc, 30)):
      d.text((x * 2 + h, y + h / 5 * j), l, fill=(0,) * 3, font=fnt)
    i += 1
  img.save('tickets.png')

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
  types = ['texture', 'live2d_sd_model', 'member_model', 'member_sd_model',
           'background', 'shader', 'skill_effect', 'stage', 'stage_effect',
           'skill_timeline', 'skill_wipe', 'adv_script',
           'gacha_performance', 'navi_motion', 'navi_timeline']
  desc = 'types of assets. supported values: ' + ', '.join(types)
  dump.add_argument('--types', dest='types', nargs='*', metavar='',
                    choices=types, default=types, help=desc)
  dirdesc = 'directory where the pkg* folders and db files are located. '
  dirdesc += 'usually /data/data/com.klab.lovelive.allstars/files/files'
  dump.add_argument('directories', nargs='*', help=dirdesc, default='.')
  dump.set_defaults(func=do_dump)

  desc = "look up strings in the game's dictionary"
  dictionary = sub.add_parser('dictionary', aliases=['dic'], help=desc)
  desc = 'strings to look up. will be returned unchanged if not found'
  dictionary.add_argument('--directory', '-d', dest='directory',
                          help=dirdesc, default='.')
  dictionary.add_argument('text', nargs='+', help=desc)
  dictionary.set_defaults(func=do_dictionary)

  desc = 'generate tickets.png with all gacha tickets. requires pillow'
  tickets = sub.add_parser('tickets', aliases=['tix'], help=desc)
  tickets.add_argument('directory', nargs='?', help=dirdesc, default='.')
  tickets.set_defaults(func=do_tickets)

  args = parser.parse_args(sys.argv[1:])
  if 'func' not in args:
    parser.parse_args(['-h'])
  args.func(args)
