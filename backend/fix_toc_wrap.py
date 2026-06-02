with open('backend/templates/VA_template/default_report.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Fix .toc-title to flex:1 with word-wrap, and remove flex-shrink:0
old_title = """    .toc-title {
      flex-shrink: 0;
    }"""

new_title = """    .toc-title {
      flex: 1;
      word-break: break-word;
      overflow-wrap: break-word;
      white-space: normal;
      padding-right: 4px;
    }"""

# Fix .toc-dots to NOT use flex:1 since title now flexes
old_dots = """    .toc-dots {
      flex: 1;
      border-bottom: 1.5px dotted #aac4dc;
      margin: 0 6px 4px;
      min-width: 20px;
    }"""

new_dots = """    .toc-dots {
      flex-shrink: 0;
      width: 40px;
      border-bottom: 1.5px dotted #aac4dc;
      margin: 0 6px 4px;
      min-width: 20px;
    }"""

# Fix toc-entry to wrap properly
old_entry = """    .toc-entry {
      display: flex;
      align-items: baseline;
      gap: 6px;
      padding: 5px 0;
      text-decoration: none;
      color: #1a1a1a;
      border-bottom: none;
      transition: background 0.1s;
    }"""

new_entry = """    .toc-entry {
      display: flex;
      align-items: flex-start;
      gap: 6px;
      padding: 5px 0;
      text-decoration: none;
      color: #1a1a1a;
      border-bottom: none;
      transition: background 0.1s;
      flex-wrap: nowrap;
    }"""

html = html.replace(old_title, new_title)
html = html.replace(old_dots, new_dots)
html = html.replace(old_entry, new_entry)

with open('backend/templates/VA_template/default_report.html', 'w', encoding='utf-8') as f:
    f.write(html)

print("Done! Verifying changes...")
# Verify
with open('backend/templates/VA_template/default_report.html', 'r', encoding='utf-8') as f:
    content = f.read()

if 'flex: 1' in content and 'word-break: break-word' in content:
    print("toc-title fix applied successfully")
else:
    print("WARNING: toc-title fix may not have applied")

if 'flex-shrink: 0' in content and 'width: 40px' in content:
    print("toc-dots fix applied successfully")
else:
    print("WARNING: toc-dots fix may not have applied")
