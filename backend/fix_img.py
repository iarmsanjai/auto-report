import base64
with open('backend/templates/VA_template/framework.png', 'rb') as f:
    img = base64.b64encode(f.read()).decode()
with open('backend/templates/VA_template/default_report.html', 'r', encoding='utf-8') as f:
    html = f.read()
html = html.replace('src="framework.png"', f'src="data:image/png;base64,{img}"')
with open('backend/templates/VA_template/default_report.html', 'w', encoding='utf-8') as f:
    f.write(html)
print("done")
