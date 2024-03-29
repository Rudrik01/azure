from flask import Flask, render_template, request
import gzip
import zlib
import rncryptor
import xml.etree.ElementTree as ET

app = Flask(__name__)

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

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('index.html', error='No file part')
        
        file = request.files['file']
        password = request.form['password']
        if len(password) == 0:
            password = ""

        if file.filename == '':
            return render_template('index.html', error='No selected file')

        if file:
            decrypted_data = decrypt_SEB(file, password)
            xml_content = decrypted_data.decode('utf-8')
            
            urls = search_urls_in_xml(xml_content)
            return render_template('result.html', urls=urls)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
