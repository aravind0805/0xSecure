def scan(filepath):
    with open(filepath, 'r') as file:
        lines = file.readlines()

    issues = []
    for i, line in enumerate(lines):
        if "eval(" in line:
            issues.append((i+1, 'Use of eval()'))
        if "$_GET" in line or "$_POST" in line:
            issues.append((i+1, 'User input without validation'))
    return issues
