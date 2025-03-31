from flask import Flask, render_template, request, send_file, redirect, url_for
import os
import gzip
import zlib
import rncryptor
import xml.etree.ElementTree as ET

app = Flask(__name__)
UPLOAD_FOLDER = 'decrypted_files'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class RNCryptorModified(rncryptor.RNCryptor):
    def post_decrypt_data(self, data):
        data = data[:-(data[-1])]
        return data

def decrypt_SEB(uploaded_file, password):
    cryptor = RNCryptorModified()
    with gzip.open(uploaded_file, 'rb') as f:
        file_content = f.read()
    decrypted_data = cryptor.decrypt(file_content[4:], password)
    decompressed_data = zlib.decompress(decrypted_data, 15 + 32)
    return decompressed_data

def search_urls_in_xml(xml_content):
    urls = []
    root = ET.fromstring(xml_content)
    for elem in root.iter():
        if elem.text and "https://" in elem.text:
            urls.append(elem.text)
    return urls

def search_hashed_passwords_in_xml(xml_content):
    hashed_passwords = {}
    root = ET.fromstring(xml_content)
    
    # Search for <key>hashedAdminPassword</key> and <key>hashedQuitPassword</key>
    for elem in root.iter():
        if elem.tag == 'key' and elem.text in ['hashedAdminPassword', 'hashedQuitPassword']:
            next_elem = next(root.iter())  # Get the next sibling element containing the password
            if next_elem is not None and next_elem.tag == 'string':
                hashed_passwords[elem.text] = next_elem.text
                
    return hashed_passwords

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('index.html', error='No file part')
        
        file = request.files['file']
        password = request.form['password'] or ""

        if file.filename == '':
            return render_template('index.html', error='No selected file')

        if file:
            decrypted_data = decrypt_SEB(file, password)
            xml_content = decrypted_data.decode('utf-8')
            urls = search_urls_in_xml(xml_content)
            hashed_passwords = search_hashed_passwords_in_xml(xml_content)

            decrypted_file_path = os.path.join(UPLOAD_FOLDER, 'decrypted.xml')
            with open(decrypted_file_path, 'w', encoding='utf-8') as f:
                f.write(xml_content)

            return render_template('result.html', urls=urls, hashed_passwords=hashed_passwords, file_link='/download')

    return render_template('index.html')

@app.route('/download')
def download_file():
    decrypted_file_path = os.path.join(UPLOAD_FOLDER, 'decrypted.xml')
    
    # Send file to the user for download
    response = send_file(decrypted_file_path, as_attachment=True)
    
    # Delete the file after sending it
    os.remove(decrypted_file_path)
    
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
