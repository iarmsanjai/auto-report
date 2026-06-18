import re
import sys
sys.stdout.reconfigure(encoding='utf-8')

content = open('templates/VA_template/default_report.html', encoding='utf-8').read()
lines = content.split('\n')
for idx, line in enumerate(lines):
    if 'page-counter' in line or 'page_counter' in line or 'total_pages' in line or 'of' in line.lower():
        # Only print if it looks relevant to page numbering
        if 'page' in line.lower() or 'counter' in line.lower() or 'total' in line.lower():
            print(f"Line {idx+1}: {line}")
