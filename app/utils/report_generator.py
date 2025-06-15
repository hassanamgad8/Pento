from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from markdown2 import markdown
from bs4 import BeautifulSoup
import json
import os
import io

def generate_pdf_report():
    # Create a buffer to store the PDF
    buffer = io.BytesIO()
    
    # Create the PDF document
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=50,
        leftMargin=50,
        topMargin=50,
        bottomMargin=50
    )

    # Load scan results
    try:
        with open('temp_scan_results.json', 'r') as f:
            data = json.load(f)
    except:
        data = {}

    # Define custom styles
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name='Title',
        fontSize=24,
        leading=30,
        spaceAfter=20,
        textColor=colors.green,
        alignment=1  # Center alignment
    ))
    styles.add(ParagraphStyle(
        name='Heading1',
        fontSize=18,
        leading=22,
        spaceAfter=12,
        textColor=colors.green
    ))
    styles.add(ParagraphStyle(
        name='Heading2',
        fontSize=16,
        leading=20,
        spaceAfter=10,
        textColor=colors.green
    ))
    styles.add(ParagraphStyle(
        name='Heading3',
        fontSize=14,
        leading=18,
        spaceAfter=8,
        textColor=colors.green
    ))
    styles.add(ParagraphStyle(
        name='Code',
        fontName='Courier',
        fontSize=9,
        leading=12,
        textColor=colors.black,
        backColor=colors.lightgrey,
        borderWidth=1,
        borderColor=colors.grey,
        borderPadding=5
    ))
    styles.add(ParagraphStyle(
        name='Normal',
        fontSize=10,
        leading=14,
        spaceAfter=6
    ))

    # Build the document content
    flow = []

    # Title and metadata
    flow.append(Paragraph("Sniper Security Scan Report", styles['Title']))
    flow.append(Paragraph(f"Target: {data.get('target', 'N/A')}", styles['Normal']))
    flow.append(Paragraph(f"Scan Time: {data.get('scan_time', 'N/A')}", styles['Normal']))
    flow.append(Spacer(1, 20))

    # Parse and render LLM Markdown as HTML → PDF
    llm_markdown = data.get('llm_report', '')
    if llm_markdown:
        html = markdown(llm_markdown, extras=["fenced-code-blocks", "tables"])
        soup = BeautifulSoup(html, 'html.parser')

        for element in soup.children:
            if element.name == 'h1':
                flow.append(Paragraph(f"<b>{element.text}</b>", styles['Heading1']))
            elif element.name == 'h2':
                flow.append(Paragraph(f"<b>{element.text}</b>", styles['Heading2']))
            elif element.name == 'h3':
                flow.append(Paragraph(f"<b>{element.text}</b>", styles['Heading3']))
            elif element.name == 'p':
                flow.append(Paragraph(element.text, styles['Normal']))
            elif element.name == 'pre':
                flow.append(Paragraph(element.text, styles['Code']))
            elif element.name == 'table':
                rows = []
                for tr in element.find_all('tr'):
                    row = [td.get_text(strip=True) for td in tr.find_all(['td', 'th'])]
                    rows.append(row)
                if rows:
                    table = Table(rows)
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.green),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('PADDING', (0, 0), (-1, -1), 6),
                    ]))
                    flow.append(Spacer(1, 6))
                    flow.append(table)
                    flow.append(Spacer(1, 12))
            elif element.name == 'ul' or element.name == 'ol':
                for li in element.find_all('li'):
                    flow.append(Paragraph(f"• {li.text}", styles['Normal']))
            elif element.name == 'code':
                flow.append(Paragraph(element.text, styles['Code']))
            elif element.text.strip():
                flow.append(Paragraph(element.text, styles['Normal']))

    # Add vulnerability summary if available
    if data.get('vulnerabilities'):
        flow.append(Paragraph("Vulnerability Summary", styles['Heading1']))
        vuln_rows = [['Severity', 'Name', 'Description']]
        for vuln in data['vulnerabilities']:
            vuln_rows.append([
                vuln.get('severity', 'N/A'),
                vuln.get('name', 'N/A'),
                vuln.get('description', 'N/A')
            ])
        vuln_table = Table(vuln_rows)
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.green),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        flow.append(Spacer(1, 12))
        flow.append(vuln_table)

    # Build the PDF
    doc.build(flow)
    
    # Get the value of the BytesIO buffer
    pdf = buffer.getvalue()
    buffer.close()
    
    return pdf 