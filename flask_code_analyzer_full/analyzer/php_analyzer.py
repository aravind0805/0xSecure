import re

def analyze_php_code(code):
    """Analyze PHP code for vulnerabilities."""
    vulnerabilities = []
    lines = code.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        line_stripped = line.strip()
        
        # SQL Injection
        if re.search(r'(mysql_query|mysqli_query).*\$_?(GET|POST)', line_stripped):
            vulnerabilities.append({
                'line': line_num,
                'issue': 'SQL Injection vulnerability',
                'severity': 'high',
                'code': line_stripped
            })
        
        # XSS
        if re.search(r'echo.*\$_?(GET|POST)', line_stripped):
            vulnerabilities.append({
                'line': line_num,
                'issue': 'XSS vulnerability',
                'severity': 'high',
                'code': line_stripped
            })
    
    return vulnerabilities