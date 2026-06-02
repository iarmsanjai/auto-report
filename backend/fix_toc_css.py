with open('backend/templates/VA_template/default_report.html', 'r', encoding='utf-8') as f:
    html = f.read()

old_css = """    .toc-list li {
      display: flex;
      justify-content: space-between;
      margin-bottom: 12px;
      font-size: 14px;
      font-weight: 600;
      position: relative;
    }"""

new_css = """    .toc-list li {
      margin-bottom: 12px;
      font-size: 14px;
      font-weight: 600;
      position: relative;
      overflow: hidden;
    }"""

html = html.replace(old_css, new_css)

old_css_a = """    .toc-list a {
      background: #f0f0f0;
      padding-right: 6px;
      color: #000;
      z-index: 1;
    }"""

new_css_a = """    .toc-list a {
      background: #f0f0f0;
      padding-right: 6px;
      color: #000;
      z-index: 1;
      float: left;
    }"""

html = html.replace(old_css_a, new_css_a)

old_css_num = """    .toc-page-num {
      background: #f0f0f0;
      padding-left: 6px;
      z-index: 1;
    }"""

new_css_num = """    .toc-page-num {
      background: #f0f0f0;
      padding-left: 6px;
      z-index: 1;
      float: right;
    }"""

html = html.replace(old_css_num, new_css_num)

with open('backend/templates/VA_template/default_report.html', 'w', encoding='utf-8') as f:
    f.write(html)

print("done")
