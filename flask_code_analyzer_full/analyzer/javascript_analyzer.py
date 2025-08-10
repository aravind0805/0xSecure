def analyze_js_code(code):
    results = []
    lines = code.split('\n')
    for idx, line in enumerate(lines, start=1):
        if 'eval(' in line or 'Function(' in line:
            results.append({
                'line': idx,
                'issue': 'Use of eval or Function constructor (dangerous)',
                'code': line.strip()
            })
        if 'document.write(' in line:
            results.append({
                'line': idx,
                'issue': 'Potential XSS via document.write',
                'code': line.strip()
            })
    return results
