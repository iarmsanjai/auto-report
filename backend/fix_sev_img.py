import base64

with open('backend/templates/VA_template/sev_rating.png', 'rb') as f:
    img = base64.b64encode(f.read()).decode()

old_block = """            <div style="text-align: center; margin: 20px 0 24px;">
              <img src="assets/sev-rating.png" alt="Severity Rating Scale"
                style="max-width: 88%; height: auto; display: inline-block;">
            </div>"""

new_block = f"""            <div style="text-align: justify; margin: 20px 0 24px;">
              <img src="data:image/png;base64,{img}" alt="Severity Rating Scale"
                style="width: 100%; height: auto; display: block;">
            </div>"""

with open('backend/templates/VA_template/default_report.html', 'r', encoding='utf-8') as f:
    html = f.read()

if old_block in html:
    html = html.replace(old_block, new_block)
    with open('backend/templates/VA_template/default_report.html', 'w', encoding='utf-8') as f:
        f.write(html)
    print("done")
else:
    print("old block not found")
