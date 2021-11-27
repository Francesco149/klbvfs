import os
import UnityPy
from PIL import Image

def unpack_all_assets(source_folder : str, destination_folder : str):
    # iterate over all files in source folder
    for root, dirs, files in os.walk(source_folder):
        for file_name in files:
            # generate file_path
            file_path = os.path.join(root, file_name)
            # load that file via UnityPy.load
            env = UnityPy.load(file_path)

            # iterate over internal objects
            for obj in env.objects:
                # process specific object types
                if obj.type.name in ["Texture2D", "Sprite"]:
                    # parse the object data
                    data = obj.read()

                    # create destination path
                    dest = os.path.join(destination_folder, data.name)

                    # make sure that the extension is correct
                    # you probably only want to do so with images/textures
                    dest, ext = os.path.splitext(dest)
                    dest = dest + ".png"

                    img = data.image
                    img.save(dest)
                if obj.type.name == "TextAsset":
                    # export asset
                    data = image.read()
                    with open(path, "wb") as f:
                        f.write(bytes(data.script))
                    # edit asset
                    fp = os.path.join(replace_dir, data.name)
                    with open(fp, "rb") as f:
                        data.script = f.read()
                    data.save()
                if obj.type.name == "Mesh":
                    mesh : Mesh = obj.read()
                    with open(f"{mesh.name}.obj", "wt", newline = "") as f:
                        # newline = "" is important
                        f.write(mesh.export())
                if obj.type.name == "Font":
                    font : Font = obj.read()
                    if font.m_FontData:
                        extension = ".ttf"
                    if font.m_FontData[0:4] == b"OTTO":
                        extension = ".otf"
                    with open(os.path.join(path, font.name+extension), "wb") as f:
                        f.write(font.m_FontData)
                

            
unpack_all_assets(".",".")
