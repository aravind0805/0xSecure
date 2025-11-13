def analyze_php_code(code):
    results = []
    lines = code.split('\n')
    for idx, line in enumerate(lines, start=1):
        if 'eval(' in line or 'exec(' in line:
            results.append({
                'line': idx,
                'issue': 'Use of eval/exec is dangerous',
                'code': line.strip()
            })
        if '$_GET' in line or '$_POST' in line:
            if 'htmlspecialchars' not in line and 'sanitize' not in line:
                results.append({
                    'line': idx,
                    'issue': 'Unsanitized input ($_GET/$_POST)',
                    'code': line.strip()
                })
    return results
