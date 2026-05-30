from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
import os
import time
import re
import html

def sanitize_for_pdf(text):
    """Clean, escape, and convert basic Markdown for ReportLab Paragraphs."""
    if not text: return ""
    
    # 1. Strip emojis and non-latin characters
    text = re.sub(r'[^\x00-\x7F]+', '', text)
    
    # 2. Escape XML special characters FIRST
    text = html.escape(text)
    
    # 3. Convert Markdown Bold: **text** -> <b>text</b>
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    
    # 4. Convert Markdown Italic: *text* -> <i>text</i>
    text = re.sub(r'(?<!\*)\*(?!\*)(.*?)(?<!\*)\*(?!\*)', r'<i>\1</i>', text)
    
    # 5. Remove any stray leading asterisks from bullet points if present after parsing
    text = re.sub(r'^\*\s+', '&bull; ', text)
    
    return text

def parse_markdown_table(table_lines, styles):
    """Converts a Markdown table into a list of Paragraphs for ReportLab Table."""
    data = []
    
    # Define specialized style for table cells (8pt for body)
    cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        textColor=colors.black
    )
    
    header_cell_style = ParagraphStyle(
        'TableHeaderCell',
        parent=styles['Normal'],
        fontSize=9,
        leading=11,
        fontName='Helvetica-Bold',
        textColor=colors.black
    )

    is_header = True
    for line in table_lines:
        if ':---' in line or '---:' in line: continue # Skip the separator line
        cells = [c.strip() for c in line.strip('|').split('|')]
        
        # Sanitize and wrap each cell in a Paragraph for auto-wrapping
        row_style = header_cell_style if is_header else cell_style
        sanitized_cells = [Paragraph(sanitize_for_pdf(c), row_style) for c in cells]
        data.append(sanitized_cells)
        is_header = False 
        
    return data

def generate_pdf_report(scan_id, scan_data):
    """Generates a professional PDF report from scan results with tabular support."""
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        
    filename = f"Security_Report_{scan_id}.pdf"
    filepath = os.path.join(reports_dir, filename)
    
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title Style (Professional Black)
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.black,
        spaceAfter=30,
        alignment=1,
        fontName='Helvetica-Bold'
    )
    
    # Subheader Style for Sections (Academic Gray)
    header_style = ParagraphStyle(
        'HeaderStyle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#333333'),
        spaceBefore=18,
        spaceAfter=12,
        alignment=0,
        borderPadding=4,
        backColor=colors.HexColor('#eeeeee'),
        fontName='Helvetica-Bold'
    )

    story.append(Paragraph("AI SecScanner - Advanced Security Audit", title_style))
    story.append(Spacer(1, 10))

    # Metadata
    story.append(Paragraph(f"<b>Scan Target:</b> {scan_data.get('target_url')}", styles['Normal']))
    story.append(Paragraph(f"<b>Scan ID:</b> {scan_id}", styles['Normal']))
    story.append(Paragraph(f"<b>Audit Date:</b> {time.ctime()}", styles['Normal']))
    story.append(Spacer(1, 20))

    # AI Report Parsing
    ai_report_raw = scan_data.get('ai_report', '')
    ai_report_raw = ai_report_raw.replace('REMEDIATION', 'RESOLUTION').replace('Remediation', 'Resolution').replace('remediation', 'resolution')
    lines = ai_report_raw.split('\n')
    
    table_buffer = []
    in_table = False

    for line in lines:
        stripped_line = line.strip()
        
        # 1. Handle Table Start/End
        if stripped_line.startswith('|'):
            in_table = True
            table_buffer.append(stripped_line)
            continue
        elif in_table:
            if table_buffer:
                table_data = parse_markdown_table(table_buffer, styles)
                if table_data:
                    # Determine column widths (using 500pt of total 612pt available on letter)
                    num_cols = len(table_data[0])
                    col_widths = [500/num_cols] * num_cols 
                    
                    t = Table(table_data, colWidths=col_widths, splitByRow=1)
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f2f2f2')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fafafa')]),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                        ('LEFTPADDING', (0, 0), (-1, -1), 6),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ]))
                    story.append(t)
                    story.append(Spacer(1, 15))
                table_buffer = []
                in_table = False
        
        # 2. Handle Headers
        if stripped_line.startswith('## '):
            story.append(Paragraph(sanitize_for_pdf(stripped_line.replace('## ', '')), header_style))
        elif stripped_line.startswith('### '):
             story.append(Paragraph(sanitize_for_pdf(stripped_line.replace('### ', '')), styles['Heading3']))
        
        # 3. Handle Regular Paragraphs (avoid buffer lines)
        elif stripped_line:
            # Clean severity markers for PDF
            p_text = stripped_line
            p_text = p_text.replace('[CRITICAL]', '!!! [CRITICAL] !!!')
            p_text = p_text.replace('[HIGH]', '[HIGH RISK]')
            p_text = p_text.replace('[MEDIUM]', '[MEDIUM RISK]')
            p_text = p_text.replace('[LOW]', '[LOW RISK]')
            
            story.append(Paragraph(sanitize_for_pdf(p_text), styles['Normal']))
            story.append(Spacer(1, 6))

    # If the report ended with a table
    if table_buffer:
        table_data = parse_markdown_table(table_buffer, styles)
        if table_data:
             num_cols = len(table_data[0])
             t = Table(table_data, colWidths=[500/num_cols] * num_cols, splitByRow=1)
             t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f2f2f2')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fafafa')]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
             ]))
             story.append(t)

    story.append(Spacer(1, 20))

    # Security Header Section (Always include)
    story.append(Paragraph("Web Header Hardening Audit", header_style))
    story.append(Spacer(1, 10))
    for issue in scan_data.get('issues', []):
        story.append(Paragraph(f"&bull; {sanitize_for_pdf(issue)}", styles['Normal']))
        story.append(Spacer(1, 4))
    
    doc.build(story)
    return filepath
