from htmldocx import HtmlToDocx
from docx import Document

html = "<h1>Test</h1><p>Hello world</p>"
document = Document()
new_parser = HtmlToDocx()
new_parser.add_html_to_document(html, document)
document.save("test.docx")
print("Saved test.docx")
