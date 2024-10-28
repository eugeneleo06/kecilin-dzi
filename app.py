from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, session, send_from_directory, after_this_request
import pydicom
import numpy as np
from PIL import Image
import io
import logging
import cv2
import os
import schedule
from datetime import datetime, timedelta
import time
from threading import Thread
import glob
from natsort import natsorted
import json
import imagecodecs
from pydicom.dataset import Dataset
import shutil
import datetime
from werkzeug.datastructures import FileStorage
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Mail, Message
import math
from werkzeug.utils import secure_filename
import zipfile
import xml.etree.ElementTree as ET


app = Flask(__name__)
app.secret_key = 'kecilinsukses'
UPLOAD_FOLDER_TMP_ROOT = 'web/uploads/tmp'
UPLOAD_FOLDER_TMP = 'uploads/tmp'
UPLOAD_FOLDER_DCM = 'web/uploads/dicom-files'
UPLOAD_FOLDER_DCM_TMP = 'web/uploads/tmp/dcm'
BASE_DIRECTORY = f'{app.root_path}/result'

app.config['UPLOAD_FOLDER_TMP_ROOT'] = UPLOAD_FOLDER_TMP_ROOT
app.config['UPLOAD_FOLDER_TMP'] = UPLOAD_FOLDER_TMP
app.config['UPLOAD_FOLDER_DCM'] = UPLOAD_FOLDER_DCM
app.config['UPLOAD_FOLDER_DCM_TMP'] = UPLOAD_FOLDER_DCM_TMP
# Configuration for Flask-Mail using Gmail SMTP
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'kecilingpt@gmail.com'  # Replace with your Gmail address
app.config['MAIL_PASSWORD'] = 'djtl imkf sxdw ftqj'  # Replace with your Gmail password or App Password
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@kecilin.id'  # Optional: Set default sender

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

conn = psycopg2.connect(
    host='localhost',
    database='kecilin_dzi',
    user='rnd',
    password='harusselalusemangat'
)

def convert_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} Bytes"
    elif size_bytes < 1024 ** 2:
        size_kb = size_bytes / 1024
        return f"{size_kb:.1f} KB"
    else:
        size_mb = size_bytes / (1024 ** 2)
        return f"{size_mb:.1f} MB"
   
@app.route('/viewer')
def viewer():
    if 'email' not in session:
        return redirect(url_for('login'))
    # Get the filename from the query parameters
    filename = request.args.get('filename')
    dzi_url = url_for('serve_files', filepath=f'{filename}/result.dzi')
    # Pass the filename to the template
    return render_template('viewer.html', dzi_url=dzi_url)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login logic here
        email = request.form['email']
        password = request.form['password']

        cur = None
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT * FROM users WHERE email = %s", (email, ))
            user = cur.fetchone()
            if user and check_password_hash(user['password'], password):
                session['email'] = user['email']
                return redirect(url_for('index'))
            else:
                flash('Invalid email or password.', 'danger')
                return redirect(url_for('login'))
        except psycopg2.Error as e:
            print('error')
            flash(f"An error occurred: {e}", 'danger')
            return redirect(url_for('login'))
        finally:
            if cur :
                cur.close()    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        token = s.dumps(email, salt='email-confirm')
        cur = None

        try:
            cur = conn.cursor()
            # Check if the email already exists
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            existing_user = cur.fetchone()

            if existing_user:
                flash('Email is already registered. Please log in or use a different email.', 'warning')
                return redirect(url_for('register'))
            
            cur.execute(
                "INSERT INTO users (email, password, is_confirmed) VALUES (%s, %s, %s)",
                (email, hashed_password, False)
            )     
            conn.commit()    
            msg = Message('Confirm your Email', sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[email])
            link = url_for('confirm_email', token=token, _external=True)
            msg.body = f'Your email confirmation link is {link}'
            mail.send(msg)
            flash('A confirmation email has been sent to your email address. Please confirm your email to complete registration.', 'info')
            return redirect(url_for('login'))
        except psycopg2.Error as e:
            print('error')
            flash(f"An error occurred: {e}", 'danger')
            return redirect(url_for('login'))
        finally:
            if cur :
                cur.close()    
    return render_template('register.html')

@app.route('/confirm_email/<token>', methods=['GET'])
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)  # Token is valid for 1 hour
    except SignatureExpired:
        flash('The confirmation link has expired.', 'danger')
        return redirect(url_for('register'))
    except BadSignature:
        flash('Invalid confirmation link.', 'danger')
        return redirect(url_for('register'))

    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if user and not user['is_confirmed']:
            cur.execute("UPDATE users SET is_confirmed = TRUE WHERE email = %s", (email,))
            conn.commit()
            flash('Your email has been confirmed. You can now log in.', 'success')
        elif user['is_confirmed']:
            flash('Your email has already been confirmed. Please log in.', 'info')
        else:
            flash('User not found.', 'danger')

    except psycopg2.Error as e:
        flash(f'Error: {e}', 'danger')
    finally:
        cur.close()

    return redirect(url_for('login'))

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('email', None)
    return redirect(url_for('login'))

@app.route('/compress')
def compress_page():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('compress.html')

@app.route('/')
def index():
    if 'email' not in session:
        return redirect(url_for('login'))
    path = os.path.abspath(BASE_DIRECTORY)
    
    items = []
    for entry in os.listdir(path):
        full_path = os.path.join(path, entry)
        
        # Only process folders/directories
        if os.path.isdir(full_path):
            last_modified = datetime.datetime.fromtimestamp(os.path.getmtime(full_path)).strftime('%Y-%m-%d')
            size = convert_size(get_folder_size(full_path))
            items.append({
                'name': entry,
                'is_dir': True,
                'size': size,  # No size for folders as requested
                'last_modified': last_modified
            })

    return render_template('index.html', items=items, current_path=path)

@app.route('/compress', methods=['POST'])
def compress():
    if 'email' not in session:
        return redirect(url_for('login'))
    if 'file' not in request.files:
        return 'No file part'
    file = request.files['file']
    filename = secure_filename(file.filename)

    if filename == '':
        return 'No selected file'
    
    file_path = os.path.join(BASE_DIRECTORY, filename)
    file.save(file_path)

    # Extract the base name without extension for the directory
    base_name = os.path.splitext(filename)[0]
    extract_dir = os.path.join(BASE_DIRECTORY, base_name)

    # Unzip the file if it’s a zip file
    if zipfile.is_zipfile(file_path):
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        os.remove(file_path)  # Optionally, remove the uploaded zip file after extraction
    else:
        return 'Uploaded file is not a ZIP archive'
    
    # COMPRESS EVERY FILE

    for root, _, files in os.walk(extract_dir):
        for file in files:
            # Check if the file is a JPEG or JPG
            if file.lower().endswith(('.jpeg', '.jpg')):
                full_path = os.path.join(root, file)
                full_path_webp = os.path.splitext(full_path)[0] + '.webp'

                try:
                    # Open the image and convert it to a supported format (e.g., PNG)
                    with Image.open(full_path) as img:
                        img.save(full_path_webp, format="WEBP", quality=60, optimize=True)

                    os.remove(full_path)
                    print(f"Compressed {full_path} to {full_path_webp}")
                except Exception as e:
                    print(f"Error compressing {full_path}: {e}")

            # Check if the file is a DZI file
            elif file.lower().endswith('.dzi'):
                full_path = os.path.join(root, file)
                modify_dzi_file(full_path)
                print(f"Modified DZI file: {file}")

    flash('Your DZI File has been compressed and saved in cloud ! ')
    return redirect(url_for('compress_page', show_modal=True))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'email' not in session:
        return redirect(url_for('login'))
    path = request.args.get('path', BASE_DIRECTORY)
    path = os.path.abspath(path)
    
    if not path.startswith(BASE_DIRECTORY):
        return "Invalid directory", 404
    
    if 'file' not in request.files:
        return redirect(request.url)

    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)

    if file:
        upload_path = os.path.join(path, file.filename)
        file.save(upload_path)

        # Check if the uploaded file is a ZIP file
        if zipfile.is_zipfile(upload_path):
            # Define the directory where the contents will be extracted
            extract_dir = os.path.join(path, os.path.splitext(file.filename)[0])

            try:
                # Create the directory to extract to, if it doesn't exist
                os.makedirs(extract_dir, exist_ok=True)

                # Unzip the file
                with zipfile.ZipFile(upload_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)

                # Optionally, remove the original ZIP file after extracting
                os.remove(upload_path)
                
            except Exception as e:
                print(f"Error extracting ZIP file: {e}")
                return "Failed to extract ZIP file", 500

        return redirect(url_for('index', path=path))

@app.route('/download')
def download_file():
    if 'email' not in session:
        return redirect(url_for('login'))
    path = request.args.get('path')
    shutil.make_archive(path, 'zip', path)
    @after_this_request
    def remove_file(response):
        try:
            os.remove(path + '.zip')
        except Exception as e:
            print(f"Error deleting file: {e}")
        return response
    
    return send_file(path + '.zip', as_attachment=True)

@app.route('/delete', methods=['POST'])
def delete_item():
    if 'email' not in session:
        return redirect(url_for('login'))
    path = request.form.get('path')
    if path and path.startswith(BASE_DIRECTORY):
        path = os.path.abspath(path)

        try:
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)  # Use rmtree to delete non-empty directories
            else:
                return jsonify(success=False, error="Path does not exist"), 404

            return jsonify(success=True), 200

        except Exception as e:
            print(f"Error deleting item: {e}")
            return jsonify(success=False, error=str(e)), 500

    return jsonify(success=False, error="Invalid path or permission denied"), 400

@app.route('/result/<path:filepath>')
def serve_files(filepath):
    return send_from_directory('result', filepath)

def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

def get_folder_size(folder_path):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(folder_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            total_size += os.path.getsize(fp)
    return total_size

def modify_dzi_file(dzi_path):
    ET.register_namespace('', "http://schemas.microsoft.com/deepzoom/2008")
    # Parse the DZI XML file
    tree = ET.parse(dzi_path)
    root = tree.getroot()

    # Example modification: add or modify an attribute (adjust as needed)
    root.set('Format', 'webp')  # Custom modification

    # Write the modified XML back to the DZI file
    tree.write(dzi_path, encoding="UTF-8", xml_declaration=True)
    print(f"Updated DZI file at {dzi_path}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=81, debug=True)

