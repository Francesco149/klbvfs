this is a proof-of-concept implementation of klab's encrypted sqlite3 vfs.
it can be used to query encrypted databases in your
`/data/data/com.klab.lovelive.allstars/files/files` directory

it assumes your directory structure is the same as it would be on your
android device to extract your master key from `shared_prefs` . so you
must dump your /data/data directory as is, or run this directly on your
phone

# usage
you need python3 and pip installed

if you have python venv:

```sh
python3 -m venv env
source env/bin/activate
```

then install dependencies

```c
python3 -m pip install -r requirements.txt
```

now you can use it

```
./klbvfs.py query masterdata.db_* "select sql from sqlite_master;"
./klbvfs.py --help
```

this also registers a python codec for klbvfs which can be used to decrypt
like so

```python
key = sqlite_key('encrypted.db')
src = codecs.open('encrypted.db', mode='rb', encoding='klbvfs', errors=key)
dst = open('decrypted.db', 'wb+')
shutil.copyfileobj(src, dst)
```

# future development
I'd like to actually make it dump all the `pkg*` files with correct names
and directory structure. the mapping between virtual paths and pkg dirs
is stored in these db's among other stuff
