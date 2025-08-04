def scan(filepath):
    with open(filepath, 'r') as file:
        lines = file.readlines()

    issues = []
    for i, line in enumerate(lines):
        if "document.write(" in line:
            issues.append((i+1, 'Use of document.write()'))
        if "innerHTML" in line:
            issues.append((i+1, 'Potential DOM-based XSS'))
    return issues
