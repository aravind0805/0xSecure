import re

def analyze_python_code(code):
    lines = code.split('\n')
    results = []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # SQL Query detection (even without input)
        if re.search(r'\b(SELECT|INSERT|UPDATE|DELETE)\b.*\bFROM\b', stripped, re.IGNORECASE):
            results.append({
                'line': i,
                'issue': 'Possible SQL Query Detected',
                'code': stripped
            })

        # SQLi pattern (weak concatenation with input)
        if re.search(r'(input\(\)|request\.form)', stripped) and '+' in stripped:
            results.append({
                'line': i,
                'issue': 'Possible SQL Injection via input()',
                'code': stripped
            })

        # Hardcoded password
        if re.search(r'password\s*=\s*[\'"].+[\'"]', stripped, re.IGNORECASE):
            results.append({
                'line': i,
                'issue': 'Hardcoded Password',
                'code': stripped
            })

        # Dangerous eval usage
        if 'eval(' in stripped:
            results.append({
                'line': i,
                'issue': 'Use of eval() (dangerous)',
                'code': stripped
            })

    return results
