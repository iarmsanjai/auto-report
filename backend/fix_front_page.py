import base64

with open('backend/templates/VA_template/front_page.png', 'rb') as f:
    img = base64.b64encode(f.read()).decode()

with open('backend/templates/VA_template/default_report.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Replace both occurrences
html = html.replace("url('front_page.png')", f"url('data:image/png;base64,{img}')")

with open('backend/templates/VA_template/default_report.html', 'w', encoding='utf-8') as f:
    f.write(html)

print("done")
