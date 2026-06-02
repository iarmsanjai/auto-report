import os

file_path = 'backend/templates/VA_template/default_report.html'
if not os.path.exists(file_path):
    file_path = 'templates/VA_template/default_report.html'

with open(file_path, 'r', encoding='utf-8') as f:
    html = f.read()

# 1. Update .toc-page padding
old_toc_page = """    .toc-page {
      position: relative;
      min-height: 297mm;
      padding: 0 0 40px;
      page-break-after: always;
      overflow: hidden;
      background: #fff;
      width: 210mm;
      margin: 0 auto 12px;
      box-shadow: 0 2px 12px rgba(0, 0, 0, 0.13);
      box-sizing: border-box;
    }"""

new_toc_page = """    .toc-page {
      position: relative;
      min-height: 297mm;
      padding: 18mm 20mm 40px 20mm;
      page-break-after: always;
      overflow: hidden;
      background: #fff;
      width: 210mm;
      margin: 0 auto 12px;
      box-shadow: 0 2px 12px rgba(0, 0, 0, 0.13);
      box-sizing: border-box;
    }"""

# 2. Update .toc-title flex
old_toc_title = """    .toc-title {
      flex: 1;
      word-break: break-word;
      overflow-wrap: break-word;
      white-space: normal;
      padding-right: 4px;
    }"""

new_toc_title = """    .toc-title {
      flex: 0 1 auto;
      word-break: break-word;
      overflow-wrap: break-word;
      white-space: normal;
      padding-right: 4px;
    }"""

# 3. Update .toc-dots flex
old_toc_dots = """    .toc-dots {
      flex-shrink: 0;
      width: 40px;
      border-bottom: 1.5px dotted #aac4dc;
      margin: 0 6px 4px;
      min-width: 20px;
    }"""

new_toc_dots = """    .toc-dots {
      flex: 1;
      border-bottom: 1.5px dotted #aac4dc;
      margin: 0 6px 4px;
      min-width: 20px;
    }"""

# Apply changes
applied = 0

if old_toc_page in html:
    html = html.replace(old_toc_page, new_toc_page)
    print("Updated .toc-page style")
    applied += 1
else:
    print("WARNING: Could not find exact match for .toc-page style")

if old_toc_title in html:
    html = html.replace(old_toc_title, new_toc_title)
    print("Updated .toc-title style")
    applied += 1
else:
    print("WARNING: Could not find exact match for .toc-title style")

if old_toc_dots in html:
    html = html.replace(old_toc_dots, new_toc_dots)
    print("Updated .toc-dots style")
    applied += 1
else:
    print("WARNING: Could not find exact match for .toc-dots style")

if applied > 0:
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"Fix completed. Applied {applied} changes.")
else:
    print("Error: No changes were applied.")
