def generate_report(issues, filename):
    return {
        'filename': filename,
        'issue_count': len(issues),
        'issues': [{'line': line, 'message': msg} for line, msg in issues]
    }
