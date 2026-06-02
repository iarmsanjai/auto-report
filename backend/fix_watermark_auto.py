import base64

with open('backend/templates/VA_template/watermark.png', 'rb') as f:
    img = base64.b64encode(f.read()).decode()

with open('backend/templates/VA_template/default_report.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Remove the old text watermark if it still exists
html = html.replace('<div class="watermark">IARM</div>', '')

watermark_html = f'\n  <div class="watermark" style="position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); opacity: 0.1; z-index: -1; pointer-events: none; user-select: none; text-align: center; width: 100%;"><img src="data:image/png;base64,{img}" style="width: 500px; height: auto; max-width: 80%;"></div>\n'

if '<body>' in html:
    html = html.replace('<body>', '<body>' + watermark_html)
    with open('backend/templates/VA_template/default_report.html', 'w', encoding='utf-8') as f:
        f.write(html)
    print("done injecting watermark")
else:
    print("body tag not found")
