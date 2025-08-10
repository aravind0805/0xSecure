def analyze_python_code(code):
    results = []
    lines = code.split('\n')
    for idx, line in enumerate(lines, start=1):
        if 'eval(' in line or 'exec(' in line:
            results.append({
                'line': idx,
                'issue': 'Use of eval/exec is dangerous',
                'code': line.strip()
            })
        if 'input(' in line and '(' in line and ')' in line:
            results.append({
                'line': idx,
                'issue': 'Unfiltered user input',
                'code': line.strip()
            })
    return results