`m_asset_package_mapping`
	`package_key` Example: `story-voice:MES/0105/mes_0105_09`
	`pack_name` Example: `k7hma0`

The `pack_name` is what we need to use to access the path to the asset.

Use the `pack_name` to find `package_key` and parse it to get a path.

```
>>> s="suit:ea/utneoh/eu"
>>> s.replace(":","/")
'suit/ea/utneoh/eu'
```

```
db = klb_sqlite(dbpath).cursor()
sel = 'select package_key from m_asset_package_mapping'
for (package_key) in db.execute(sel):
	

 FROM table_name AS alias_name;

"SELECT m_asset_package_mapping.package_key,"+table+".pack_name, "+table+".head, "+table+".size, "+table+".key1, "+table+".key2, FROM "+table+" INNER JOIN pack_name ON m_asset_package_mapping.pack_name = "+table+".pack_name; 


SELECT m_asset_package_mapping.package_key,"+table+".pack_name, "+table+".head, "+table+".size, "+table+".key1, "+table+".key2 
FROM "+table+" INNER JOIN m_asset_package_mapping ON m_asset_package_mapping.pack_name = "+table+".pack_name

For getting the names of the cards / characters we gotta add the database file `m_dictionary` to the dump tables. This gives us the `id` record that contains the id the folders are named. Then with this we can use what it returns `message` to get the name of the folder


