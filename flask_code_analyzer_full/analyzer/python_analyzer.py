import re

def analyze_python_code(code):
    results = []
    lines = code.split('\n')

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()

        # 1. Detect eval() usage
        if "eval(" in stripped:
            results.append({
                'line': lineno,
                'issue': '⚠️ Dangerous use of eval()',
                'code': stripped
            })

        # 2. Detect exec() usage
        if "exec(" in stripped:
            results.append({
                'line': lineno,
                'issue': '⚠️ Dangerous use of exec()',
                'code': stripped
            })

        # 3. Detect hardcoded credentials
        if re.search(r'(password|passwd|pwd|secret|token)\s*=\s*[\'"]{1}.+[\'"]{1}', stripped, re.IGNORECASE):
            results.append({
                'line': lineno,
                'issue': '🔐 Hardcoded password or secret detected',
                'code': stripped
            })

        # 4. Detect SQL injection (string concatenation in SQL query)
        if (
            re.search(r"(SELECT|INSERT|DELETE|UPDATE).+['\"]\s*\+\s*\w+", stripped, re.IGNORECASE)
            or re.search(r"\w+\s*=\s*['\"].*\+\s*\w+", stripped)
        ):
            results.append({
                'line': lineno,
                'issue': '💣 Possible SQL Injection via string concatenation',
                'code': stripped
            })

        # 5. Detect use of raw SQL execute (without parameters)
        if 'execute(' in stripped and '+' in stripped:
            results.append({
                'line': lineno,
                'issue': '💥 Unparameterized SQL query (possible injection)',
                'code': stripped
            })

    return results
