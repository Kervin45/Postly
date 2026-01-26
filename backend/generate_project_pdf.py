"""
Generate a comprehensive PDF with project structure and all code files
"""
import os
import sys
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Preformatted
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# Get project root
PROJECT_ROOT = Path(__file__).parent.parent

def get_directory_structure(path, prefix="", ignore_dirs={'.git', '__pycache__', 'node_modules', '.venv', 'venv', '.env', 'instance', '.next', 'dist', 'build'}):
    """Generate a text representation of directory structure"""
    items = []
    path = Path(path)
    
    try:
        entries = sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name))
    except PermissionError:
        return items
    
    for i, entry in enumerate(entries):
        if entry.name.startswith('.') and entry.name not in {'.gitignore', '.env.example'}:
            continue
        if entry.name in ignore_dirs:
            continue
            
        is_last = i == len(entries) - 1
        current = "└── " if is_last else "├── "
        next_prefix = "    " if is_last else "│   "
        
        items.append(prefix + current + entry.name + ("/" if entry.is_dir() else ""))
        
        if entry.is_dir():
            items.extend(get_directory_structure(entry, prefix + next_prefix, ignore_dirs))
    
    return items

def get_code_files(base_path, extensions={'.py', '.jsx', '.js', '.json', '.css', '.html', '.yaml', '.yml', '.txt'}, 
                   ignore_dirs={'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'instance', '.next', 'dist', 'build', '.env'}):
    """Get all code files in the project"""
    files = []
    base_path = Path(base_path)
    
    for root, dirs, filenames in os.walk(base_path):
        # Remove ignored directories
        dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith('.')]
        
        for filename in sorted(filenames):
            if any(filename.endswith(ext) for ext in extensions):
                file_path = Path(root) / filename
                rel_path = file_path.relative_to(PROJECT_ROOT)
                files.append(rel_path)
    
    return sorted(files)

def read_file_content(file_path, max_lines=500):
    """Read file content with line limit"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        if len(lines) > max_lines:
            content = ''.join(lines[:max_lines])
            content += f"\n... ({len(lines) - max_lines} more lines)\n"
        else:
            content = ''.join(lines)
        return content
    except Exception as e:
        return f"Error reading file: {str(e)}"

def create_pdf():
    """Create the PDF document"""
    output_path = PROJECT_ROOT / "project_documentation.pdf"
    
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch,
        title="Postly v2 - Project Documentation"
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=12,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#3b82f6'),
        spaceAfter=10,
        spaceBefore=10,
        fontName='Helvetica-Bold'
    )
    
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading3'],
        fontSize=12,
        textColor=colors.HexColor('#475569'),
        spaceAfter=8,
        spaceBefore=8,
        fontName='Helvetica-Bold'
    )
    
    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        spaceAfter=6,
        leftIndent=12,
        rightIndent=12,
        backColor=colors.HexColor('#f1f5f9'),
        borderPadding=8
    )
    
    # Content
    content = []
    
    # Title Page
    content.append(Spacer(1, 1*inch))
    content.append(Paragraph("Postly v2", title_style))
    content.append(Paragraph("Project Documentation", styles['Heading2']))
    content.append(Spacer(1, 0.3*inch))
    content.append(Paragraph(f"Generated: {__import__('datetime').datetime.now().strftime('%B %d, %Y')}", styles['Normal']))
    content.append(Spacer(1, 0.5*inch))
    
    # Project Overview
    content.append(Paragraph("Project Overview", heading_style))
    content.append(Paragraph(
        "Postly v2 is a social media platform built with Flask (backend) and React (frontend). "
        "It features user authentication with JWT, post creation/management, and a responsive feed interface.",
        styles['Normal']
    ))
    content.append(Spacer(1, 0.3*inch))
    
    # Tech Stack
    content.append(Paragraph("Technology Stack", heading_style))
    tech_text = """
    <b>Backend:</b> Flask, Flask-SQLAlchemy, Flask-JWT-Extended<br/>
    <b>Frontend:</b> React, React Router, Vite<br/>
    <b>Database:</b> SQLite<br/>
    <b>Styling:</b> CSS (inline styles in React components)<br/>
    """
    content.append(Paragraph(tech_text, styles['Normal']))
    content.append(Spacer(1, 0.2*inch))
    
    # Directory Structure
    content.append(PageBreak())
    content.append(Paragraph("Project Structure", heading_style))
    
    struct_lines = get_directory_structure(PROJECT_ROOT)
    struct_text = "postlyv2/\n" + "\n".join(struct_lines[:100])  # Limit displayed lines
    
    struct_preformatted = Preformatted(struct_text, code_style)
    content.append(struct_preformatted)
    content.append(Spacer(1, 0.3*inch))
    
    # Code Files
    content.append(PageBreak())
    content.append(Paragraph("Source Code Files", heading_style))
    content.append(Spacer(1, 0.2*inch))
    
    # Get and organize files by directory
    code_files = get_code_files(PROJECT_ROOT)
    
    # Group files by directory
    files_by_dir = {}
    for file_path in code_files:
        dir_name = str(file_path.parent)
        if dir_name not in files_by_dir:
            files_by_dir[dir_name] = []
        files_by_dir[dir_name].append(file_path)
    
    # Add files for each directory
    for dir_name in sorted(files_by_dir.keys()):
        files = files_by_dir[dir_name]
        
        for file_path in files:
            content.append(Spacer(1, 0.15*inch))
            content.append(Paragraph(f"📄 {file_path}", subheading_style))
            
            file_content = read_file_content(PROJECT_ROOT / file_path, max_lines=200)
            
            # Create a preformatted block with syntax-like styling
            file_preformatted = Preformatted(file_content, code_style)
            content.append(file_preformatted)
            content.append(Spacer(1, 0.15*inch))
    
    # Build PDF
    doc.build(content)
    print(f"✅ PDF generated successfully: {output_path}")
    return str(output_path)

if __name__ == "__main__":
    try:
        # Check if reportlab is installed
        import reportlab
    except ImportError:
        print("Installing reportlab...")
        os.system(f"{sys.executable} -m pip install reportlab")
    
    create_pdf()
