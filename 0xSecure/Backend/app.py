from flask import Flask, request, render_template, jsonify
import os
from Scanner import php_scanner, js_scanner, report_generator

UPLOAD_FOLDER = '../uploads'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/')
def index():
    return render_template('index.html')  # if using templates


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    filename = file.filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Determine file type
    if filename.endswith('.php'):
        scan_result = php_scanner.scan(filepath)
    elif filename.endswith('.js'):
        scan_result = js_scanner.scan(filepath)
    else:
        return jsonify({'error': 'Unsupported file type'}), 400

    report = report_generator.generate_report(scan_result, filename)
    return jsonify(report)


if __name__ == '__main__':
    app.run(debug=True)
