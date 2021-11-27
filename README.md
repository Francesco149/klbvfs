This is a proof-of-concept implementation of klab's encrypted sqlite3 vfs (virtual file system). It can be used to query encrypted databases in your
`/data/data/com.klab.lovelive.allstars/files/files` directory

It assumes your directory structure is the same as it would be on your
android device to extract your master key from `shared_prefs` . so you
must dump your `/data/data` directory as is, or run this directly on your
phone.

To get all the files in the right directory, get all the `pkg` files and `.db.*` files in one folder, then copy the `klbvfs.py` file to that directory.

# Usage
You need python3 and pip installed

If you have python venv:

```sh
python3 -m venv env
source env/bin/activate
```

Then install dependencies

```c
python3 -m pip install -r requirements.txt
```

Now you can use it

```
./klbvfs.py query masterdata.db_* "select sql from sqlite_master;"
./klbvfs decrypt *.db_*.db
./klbvfs.py --help
./klbvfs.py dump [--types [[...]]] [directories [directories ...]]
```

Example (while in the directory with all the `pkg` folders):

```
./klbvfs.py dump --types=member_model
```

This also registers a python codec for klbvfs which can be used to decrypt
like so

```python
key = sqlite_key('encrypted.db')
src = codecs.open('encrypted.db', mode='rb', encoding='klbvfs', errors=key)
dst = open('decrypted.db', 'wb+')
shutil.copyfileobj(src, dst)
```

# Future development
I'd like to actually make it dump all the `pkg*` files with correct names
and directory structure. the mapping between virtual paths and pkg dirs
is stored in these db's among other stuff
