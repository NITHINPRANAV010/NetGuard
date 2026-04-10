from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf_report(data, filename="report.pdf"):
    doc = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()

    elements = []

    # Title
    elements.append(Paragraph("Vulnerability Scan Report", styles['Title']))
    elements.append(Spacer(1, 12))

    # URL
    elements.append(Paragraph(f"Target URL: {data['url']}", styles['Normal']))
    elements.append(Spacer(1, 12))

    # Vulnerabilities
    elements.append(Paragraph("Detected Vulnerabilities:", styles['Heading2']))

    for vuln in data["vulnerabilities"]:
        text = f"- {vuln['type']} (Severity: {vuln['severity']})"
        elements.append(Paragraph(text, styles['Normal']))
        elements.append(Spacer(1, 10))

    doc.build(elements)

    return filename
