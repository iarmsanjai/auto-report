import sys
sys.stdout.reconfigure(encoding='utf-8')

content = open('templates/VA_template/default_report.html', encoding='utf-8').read()
lines = content.split('\n')
for idx in range(600, 626):
    print(f"{idx+1}: {lines[idx]}")
