import fitz  # PyMuPDF
import sys
import os

def extract_pdf_images(pdf_path, out_dir):
    try:
        os.makedirs(out_dir, exist_ok=True)
        doc = fitz.open(pdf_path)
        print(f"Total Pages: {len(doc)}")
        
        for i in range(len(doc)):
            page = doc[i]
            images = page.get_images(full=True)
            for img_idx, img in enumerate(images):
                xref = img[0]
                base_image = doc.extract_image(xref)
                image_bytes = base_image["image"]
                image_ext = base_image["ext"]
                image_filename = os.path.join(out_dir, f"page{i+1}_img{img_idx+1}.{image_ext}")
                with open(image_filename, "wb") as f:
                    f.write(image_bytes)
                print(f"Extracted: {image_filename}")
                
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    extract_pdf_images(sys.argv[1], sys.argv[2])
