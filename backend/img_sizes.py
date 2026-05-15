from PIL import Image
import os
path = "templates/VA_template/assets"
for f in sorted(os.listdir(path)):
    img_path = os.path.join(path, f)
    try:
        size = Image.open(img_path).size
        print(f"{f}: {size}")
    except:
        pass
