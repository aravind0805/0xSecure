import re

def analyze_js_code(code):
    """Analyze JavaScript code for vulnerabilities."""
    vulnerabilities = []
    lines = code.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        line_stripped = line.strip()
        
        # XSS via innerHTML
        if re.search(r'innerHTML\s*=.*\+', line_stripped):
            vulnerabilities.append({
                'line': line_num,
                'issue': 'Potential XSS via innerHTML',
                'severity': 'high',
                'code': line_stripped
            })
        
        # eval() usage
        if re.search(r'\beval\s*\(', line_stripped):
            vulnerabilities.append({
                'line': line_num,
                'issue': 'Dangerous eval() usage',
                'severity': 'high',
                'code': line_stripped
            })
    
    return vulnerabilities