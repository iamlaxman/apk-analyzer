from flask import Flask, request, jsonify, send_file, render_template
from flask_cors import CORS
import os
import zipfile
import shutil
import json
import tempfile
import hashlib
import re
import mimetypes
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import threading
import time
import logging
import sys
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Try Flask-Compress
try:
    from flask_compress import Compress
    Compress(app)
    logger.info("Compression enabled")
except ImportError:
    logger.warning("Flask-Compress not available")

# ============ Configuration ============
UPLOAD_FOLDER = '/tmp/apk_uploads'
EXTRACT_FOLDER = '/tmp/apk_extracted'
PORT = int(os.environ.get('PORT', 10000))

# Create directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(EXTRACT_FOLDER, exist_ok=True)

logger.info(f"Upload folder: {UPLOAD_FOLDER}")
logger.info(f"Extract folder: {EXTRACT_FOLDER}")
logger.info(f"Port: {PORT}")

class Config:
    UPLOAD_FOLDER = UPLOAD_FOLDER
    EXTRACT_FOLDER = EXTRACT_FOLDER
    ALLOWED_EXTENSIONS = {'apk'}
    MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB (Render allows up to 500MB)
    SESSION_TIMEOUT = 1800
    MAX_SESSIONS = 10

# IMPORTANT: Set MAX_CONTENT_LENGTH before other config
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_FILE_SIZE
app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER
app.config['EXTRACT_FOLDER'] = Config.EXTRACT_FOLDER
app.config['SECRET_KEY'] = 'apk-analyzer-production-key-2024'

# Increase request timeout for large uploads
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Store sessions
analysis_cache = {}
session_timestamps = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def get_session_id():
    return hashlib.sha256(os.urandom(32)).hexdigest()[:16]

def get_extract_path(session_id):
    return os.path.join(EXTRACT_FOLDER, session_id)

def get_apk_path(session_id):
    return os.path.join(UPLOAD_FOLDER, f"{session_id}.apk")

def format_size(size):
    try:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    except:
        return "Unknown"

def get_file_icon(filename):
    ext = os.path.splitext(filename)[1].lower()
    icons = {
        '.dex': '📦', '.xml': '📋', '.png': '🖼️', '.jpg': '🖼️',
        '.json': '📊', '.so': '⚙️', '.js': '📜', '.html': '🌐',
        '.css': '🎨', '.kt': '🔷', '.java': '☕', '.txt': '📄',
        '.arsc': '📚', '.pro': '🔒', '.sf': '✍️', '.rsa': '🔑'
    }
    return icons.get(ext, '📄')

# ============ Routes ============

@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Template error: {e}")
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>APK Analyzer</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                    background: #fff; 
                    color: #000;
                    min-height: 100vh;
                }
                .container { max-width: 800px; margin: 0 auto; padding: 20px; }
                h1 { font-size: 2rem; margin: 20px 0; }
                #dropZone { 
                    border: 3px dashed #000; 
                    padding: 60px 20px; 
                    text-align: center; 
                    cursor: pointer; 
                    border-radius: 6px;
                    transition: all 0.3s;
                    background: #fff;
                }
                #dropZone:hover, #dropZone.dragover { 
                    border-color: #FFD1BA; 
                    background: #FFF0E8;
                }
                #dropZone h2 { margin: 10px 0; }
                #dropZone p { color: #666; }
                #progress { display: none; margin: 30px 0; }
                .progress-bar {
                    height: 24px;
                    background: #f0f0f0;
                    border-radius: 12px;
                    overflow: hidden;
                    border: 2px solid #000;
                }
                .progress-fill {
                    height: 100%;
                    background: #4CAF50;
                    width: 0%;
                    transition: width 0.3s;
                    border-radius: 10px;
                }
                .progress-text { text-align: center; margin-top: 10px; font-weight: 600; }
                #results { display: none; }
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 10px;
                    margin: 20px 0;
                }
                .stat-card {
                    border: 2px solid #000;
                    padding: 15px;
                    border-radius: 6px;
                    background: #fff;
                }
                .stat-card strong { display: block; font-size: 0.85rem; text-transform: uppercase; color: #666; }
                .stat-card span { font-size: 1.5rem; font-weight: 700; }
                .file-item {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 12px 15px;
                    border: 2px solid #000;
                    margin: 5px 0;
                    border-radius: 6px;
                    background: #fff;
                }
                .file-item:hover { background: #f9f9f9; }
                .btn {
                    padding: 10px 20px;
                    font-weight: 600;
                    border: 2px solid #000;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 14px;
                    transition: all 0.2s;
                    background: #fff;
                }
                .btn:hover { background: #f0f0f0; }
                .btn-primary { background: #FFD1BA; }
                .btn-primary:hover { background: #D4A68A; }
                .btn-download { 
                    background: #4CAF50; 
                    color: #fff; 
                    border: 2px solid #000;
                    padding: 5px 15px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-weight: 600;
                }
                .btn-download:hover { background: #45a049; }
                .error { 
                    background: #FEF0F2; 
                    border: 2px solid #C70036; 
                    padding: 15px; 
                    border-radius: 6px;
                    color: #C70036;
                    margin: 10px 0;
                }
                #fileInput { display: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📱 APK Analyzer Pro</h1>
                
                <div id="dropZone" onclick="document.getElementById('fileInput').click()">
                    <div style="font-size: 64px;">📤</div>
                    <h2>Drop APK File Here</h2>
                    <p>or click to browse (Max 500MB)</p>
                    <input type="file" id="fileInput" accept=".apk" onchange="uploadFile(this)">
                </div>
                
                <div id="progress">
                    <div class="progress-bar">
                        <div class="progress-fill" id="progressFill"></div>
                    </div>
                    <p class="progress-text" id="progressText">Preparing...</p>
                </div>
                
                <div id="error" class="error" style="display:none;"></div>
                
                <div id="results">
                    <h2>📊 Analysis Results</h2>
                    <div class="stats-grid" id="stats"></div>
                    
                    <h3 style="margin-top: 30px;">📁 Files</h3>
                    <div id="fileList"></div>
                    
                    <div style="margin-top: 20px; display: flex; gap: 10px;">
                        <button class="btn btn-primary" onclick="downloadAll()">⬇️ Download All Files</button>
                        <button class="btn" onclick="location.reload()">🔄 Analyze Another APK</button>
                    </div>
                </div>
            </div>
            
            <script>
                const API = '/api';
                let sessionId = null;
                
                const dropZone = document.getElementById('dropZone');
                const fileInput = document.getElementById('fileInput');
                
                // Drag and drop events
                dropZone.addEventListener('dragover', (e) => {
                    e.preventDefault();
                    dropZone.classList.add('dragover');
                });
                
                dropZone.addEventListener('dragleave', (e) => {
                    e.preventDefault();
                    dropZone.classList.remove('dragover');
                });
                
                dropZone.addEventListener('drop', (e) => {
                    e.preventDefault();
                    dropZone.classList.remove('dragover');
                    const files = e.dataTransfer.files;
                    if (files.length > 0) {
                        fileInput.files = files;
                        uploadFile(fileInput);
                    }
                });
                
                async function uploadFile(input) {
                    const file = input.files[0];
                    if (!file) return;
                    
                    if (!file.name.toLowerCase().endsWith('.apk')) {
                        showError('Please upload an APK file');
                        return;
                    }
                    
                    console.log('Uploading:', file.name, 'Size:', (file.size / 1024 / 1024).toFixed(2) + 'MB');
                    
                    // Hide dropzone, show progress
                    document.getElementById('dropZone').style.display = 'none';
                    document.getElementById('error').style.display = 'none';
                    document.getElementById('results').style.display = 'none';
                    document.getElementById('progress').style.display = 'block';
                    
                    updateProgress(5, 'Uploading APK...');
                    
                    try {
                        const formData = new FormData();
                        formData.append('file', file);
                        
                        const response = await fetch(API + '/upload', {
                            method: 'POST',
                            body: formData
                        });
                        
                        const data = await response.json();
                        
                        if (!response.ok) {
                            throw new Error(data.error || 'Upload failed (Status: ' + response.status + ')');
                        }
                        
                        sessionId = data.session_id;
                        console.log('Session:', sessionId);
                        
                        updateProgress(60, 'Analyzing APK...');
                        
                        // Get full analysis
                        const analysisRes = await fetch(API + '/analyze/' + sessionId);
                        const analysisData = await analysisRes.json();
                        
                        if (!analysisRes.ok) {
                            throw new Error(analysisData.error || 'Analysis failed');
                        }
                        
                        updateProgress(90, 'Building results...');
                        showResults(analysisData.analysis);
                        
                        updateProgress(100, 'Complete! ✅');
                        
                        setTimeout(() => {
                            document.getElementById('progress').style.display = 'none';
                            document.getElementById('results').style.display = 'block';
                        }, 500);
                        
                    } catch (error) {
                        console.error('Upload error:', error);
                        showError('Error: ' + error.message);
                        document.getElementById('progress').style.display = 'none';
                        document.getElementById('dropZone').style.display = 'block';
                    }
                }
                
                function updateProgress(percent, text) {
                    document.getElementById('progressFill').style.width = percent + '%';
                    document.getElementById('progressText').textContent = text;
                }
                
                function showError(message) {
                    const errorDiv = document.getElementById('error');
                    errorDiv.textContent = message;
                    errorDiv.style.display = 'block';
                }
                
                function showResults(analysis) {
                    const info = analysis.basic_info;
                    
                    document.getElementById('stats').innerHTML = `
                        <div class="stat-card">
                            <strong>Package</strong>
                            <span style="font-size:1rem; word-break:break-all;">${info.package_name}</span>
                        </div>
                        <div class="stat-card">
                            <strong>Version</strong>
                            <span>${info.version_name} (${info.version_code})</span>
                        </div>
                        <div class="stat-card">
                            <strong>SDK</strong>
                            <span>Min: ${info.min_sdk} | Target: ${info.target_sdk}</span>
                        </div>
                        <div class="stat-card">
                            <strong>Permissions</strong>
                            <span>${analysis.permissions.length}</span>
                        </div>
                        <div class="stat-card">
                            <strong>Activities</strong>
                            <span>${analysis.components.activities.length}</span>
                        </div>
                        <div class="stat-card">
                            <strong>Size</strong>
                            <span>${formatSize(analysis.total_size)}</span>
                        </div>
                    `;
                    
                    // File list
                    let html = '';
                    if (analysis.file_structure && analysis.file_structure.length > 0) {
                        analysis.file_structure.forEach(file => {
                            html += `
                                <div class="file-item">
                                    <span>${file.icon || '📄'} ${file.name}</span>
                                    <span style="display:flex; align-items:center; gap:10px;">
                                        ${file.size_formatted ? '<span style="color:#666;">' + file.size_formatted + '</span>' : ''}
                                        ${file.type === 'file' ? 
                                            `<button class="btn-download" onclick="downloadFile('${file.path}')">⬇️ Download</button>` : 
                                            `<span style="color:#666;">📁 Folder</span>`}
                                    </span>
                                </div>
                            `;
                        });
                    } else {
                        html = '<p>No files found</p>';
                    }
                    document.getElementById('fileList').innerHTML = html;
                }
                
                function downloadFile(path) {
                    if (!sessionId) return;
                    const url = API + '/download/' + sessionId + '/' + encodeURIComponent(path);
                    console.log('Downloading:', url);
                    window.open(url, '_blank');
                }
                
                function downloadAll() {
                    if (!sessionId) return;
                    const url = API + '/download-all/' + sessionId;
                    console.log('Downloading all:', url);
                    window.open(url, '_blank');
                }
                
                function formatSize(bytes) {
                    if (!bytes || bytes === 0) return '0 B';
                    const sizes = ['B', 'KB', 'MB', 'GB'];
                    const i = Math.floor(Math.log(bytes) / Math.log(1024));
                    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + sizes[i];
                }
            </script>
        </body>
        </html>
        ''', 200

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'sessions': len(analysis_cache),
        'version': '1.0.0',
        'max_upload_mb': Config.MAX_FILE_SIZE / 1024 / 1024
    })

@app.route('/api/upload', methods=['POST'])
def upload_apk():
    logger.info("=" * 50)
    logger.info("Upload endpoint called")
    
    try:
        # Log request details
        logger.info(f"Content Length: {request.content_length}")
        logger.info(f"Content Type: {request.content_type}")
        
        if 'file' not in request.files:
            logger.error("No file in request.files")
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            logger.error("Empty filename")
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            logger.error(f"Invalid file type: {file.filename}")
            return jsonify({'error': 'Only .apk files are allowed'}), 400
        
        # Generate session
        session_id = get_session_id()
        filename = secure_filename(file.filename)
        apk_path = get_apk_path(session_id)
        
        logger.info(f"Session: {session_id}")
        logger.info(f"Filename: {filename}")
        logger.info(f"Saving to: {apk_path}")
        
        # Save file
        file.save(apk_path)
        logger.info("File saved successfully")
        
        # Check file size
        file_size = os.path.getsize(apk_path)
        file_size_mb = file_size / 1024 / 1024
        logger.info(f"File size: {file_size} bytes ({file_size_mb:.2f} MB)")
        
        if file_size == 0:
            os.remove(apk_path)
            logger.error("Empty file (0 bytes)")
            return jsonify({'error': 'File is empty (0 bytes)'}), 400
        
        if file_size > Config.MAX_FILE_SIZE:
            os.remove(apk_path)
            logger.error(f"File too large: {file_size_mb:.2f} MB")
            return jsonify({
                'error': f'File too large ({file_size_mb:.1f} MB). Maximum size is {Config.MAX_FILE_SIZE / 1024 / 1024:.0f} MB'
            }), 413
        
        # Extract APK
        extract_path = get_extract_path(session_id)
        os.makedirs(extract_path, exist_ok=True)
        logger.info(f"Extracting to: {extract_path}")
        
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        
        # Count extracted files
        file_count = sum([len(files) for r, d, files in os.walk(extract_path)])
        logger.info(f"Extracted {file_count} files")
        
        # Build analysis
        analysis = {
            'basic_info': {
                'package_name': filename.replace('.apk', ''),
                'version_name': 'Unknown',
                'version_code': 'Unknown',
                'min_sdk': 'Unknown',
                'target_sdk': 'Unknown',
                'app_name': filename.replace('.apk', '')
            },
            'permissions': [],
            'components': {
                'activities': [],
                'services': [],
                'receivers': [],
                'providers': []
            },
            'tech_stack': {'languages': ['Java'], 'frameworks': [], 'libraries': []},
            'dex_analysis': {'total_classes': 0, 'total_methods': 0, 'dex_files': []},
            'security': [],
            'file_structure': [],
            'total_size': file_size,
            'extracted_files': file_count
        }
        
        # Parse manifest
        manifest_path = os.path.join(extract_path, 'AndroidManifest.xml')
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, 'rb') as f:
                    content = f.read()
                    text = content.decode('latin-1', errors='ignore')
                    
                    pkg_match = re.search(r'package="([^"]+)"', text)
                    if pkg_match:
                        analysis['basic_info']['package_name'] = pkg_match.group(1)
                    
                    ver_match = re.search(r'versionName="([^"]+)"', text)
                    if ver_match:
                        analysis['basic_info']['version_name'] = ver_match.group(1)
                    
                    code_match = re.search(r'versionCode="(\d+)"', text)
                    if code_match:
                        analysis['basic_info']['version_code'] = code_match.group(1)
                    
                    min_match = re.search(r'minSdkVersion="(\d+)"', text)
                    if min_match:
                        analysis['basic_info']['min_sdk'] = min_match.group(1)
                    
                    target_match = re.search(r'targetSdkVersion="(\d+)"', text)
                    if target_match:
                        analysis['basic_info']['target_sdk'] = target_match.group(1)
                    
                    permissions = re.findall(r'uses-permission.*?android:name="([^"]+)"', text)
                    analysis['permissions'] = permissions
                    
                    activities = re.findall(r'<activity.*?android:name="([^"]+)"', text)
                    analysis['components']['activities'] = activities
                    
                    services = re.findall(r'<service.*?android:name="([^"]+)"', text)
                    analysis['components']['services'] = services
                    
                    receivers = re.findall(r'<receiver.*?android:name="([^"]+)"', text)
                    analysis['components']['receivers'] = receivers
                    
                    providers = re.findall(r'<provider.*?android:name="([^"]+)"', text)
                    analysis['components']['providers'] = providers
                    
                    logger.info(f"Manifest: {len(permissions)} permissions, {len(activities)} activities")
            except Exception as e:
                logger.error(f"Manifest error: {e}")
        
        # Analyze DEX files
        for file_name in os.listdir(extract_path):
            if file_name.endswith('.dex'):
                dex_path = os.path.join(extract_path, file_name)
                analysis['dex_analysis']['dex_files'].append({
                    'name': file_name,
                    'size': os.path.getsize(dex_path),
                    'class_count': 0,
                    'method_count': 0,
                    'classes': []
                })
        
        # Detect tech stack
        lib_path = os.path.join(extract_path, 'lib')
        if os.path.exists(lib_path):
            if 'C/C++ (Native)' not in analysis['tech_stack']['languages']:
                analysis['tech_stack']['languages'].append('C/C++ (Native)')
            for arch in os.listdir(lib_path):
                arch_path = os.path.join(lib_path, arch)
                if os.path.isdir(arch_path):
                    for lib in os.listdir(arch_path):
                        lib_lower = lib.lower()
                        if 'flutter' in lib_lower and 'Flutter' not in analysis['tech_stack']['frameworks']:
                            analysis['tech_stack']['frameworks'].append('Flutter')
                        elif ('react' in lib_lower or 'hermes' in lib_lower) and 'React Native' not in analysis['tech_stack']['frameworks']:
                            analysis['tech_stack']['frameworks'].append('React Native')
        
        # Check for Kotlin
        for root, dirs, files in os.walk(extract_path):
            if any(f.endswith('.kotlin_module') for f in files):
                if 'Kotlin' not in analysis['tech_stack']['languages']:
                    analysis['tech_stack']['languages'].append('Kotlin')
                break
        
        # File structure
        for item in sorted(os.listdir(extract_path)):
            item_path = os.path.join(extract_path, item)
            if os.path.isfile(item_path):
                analysis['file_structure'].append({
                    'name': item,
                    'path': item,
                    'type': 'file',
                    'size': os.path.getsize(item_path),
                    'size_formatted': format_size(os.path.getsize(item_path)),
                    'icon': get_file_icon(item)
                })
            elif os.path.isdir(item_path):
                analysis['file_structure'].append({
                    'name': item,
                    'path': item,
                    'type': 'directory',
                    'icon': '📁'
                })
        
        # Store
        analysis_cache[session_id] = analysis
        session_timestamps[session_id] = datetime.now()
        
        logger.info(f"Analysis complete: {analysis['basic_info']['package_name']}")
        logger.info("=" * 50)
        
        return jsonify({
            'status': 'success',
            'session_id': session_id,
            'filename': filename,
            'analysis': analysis  # Return analysis immediately
        })
        
    except zipfile.BadZipFile:
        logger.error("Bad ZIP file")
        return jsonify({'error': 'Invalid APK file - not a valid ZIP archive'}), 400
    except Exception as e:
        logger.error(f"Upload error: {traceback.format_exc()}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/analyze/<session_id>', methods=['GET'])
def get_analysis(session_id):
    try:
        if session_id not in analysis_cache:
            return jsonify({'error': 'Session not found'}), 404
        
        session_timestamps[session_id] = datetime.now()
        
        return jsonify({
            'status': 'success',
            'analysis': analysis_cache[session_id]
        })
    except Exception as e:
        logger.error(f"Analysis error: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/<session_id>', methods=['GET'])
def get_files(session_id):
    try:
        if session_id not in analysis_cache:
            return jsonify({'error': 'Session not found'}), 404
        
        path = request.args.get('path', '')
        extract_path = get_extract_path(session_id)
        
        if not os.path.exists(extract_path):
            return jsonify({'error': 'Session expired'}), 404
        
        current_path = os.path.join(extract_path, path) if path else extract_path
        
        if not os.path.abspath(current_path).startswith(os.path.abspath(extract_path)):
            return jsonify({'error': 'Invalid path'}), 403
        
        if not os.path.exists(current_path):
            return jsonify({'error': 'Path not found'}), 404
        
        files = []
        if os.path.isfile(current_path):
            files.append({
                'name': os.path.basename(current_path),
                'path': path,
                'type': 'file',
                'size': os.path.getsize(current_path),
                'size_formatted': format_size(os.path.getsize(current_path)),
                'icon': get_file_icon(os.path.basename(current_path))
            })
        else:
            for item in sorted(os.listdir(current_path)):
                item_path = os.path.join(current_path, item)
                rel_path = os.path.relpath(item_path, extract_path).replace('\\', '/')
                
                if os.path.isfile(item_path):
                    files.append({
                        'name': item,
                        'path': rel_path,
                        'type': 'file',
                        'size': os.path.getsize(item_path),
                        'size_formatted': format_size(os.path.getsize(item_path)),
                        'icon': get_file_icon(item)
                    })
                else:
                    files.append({
                        'name': item,
                        'path': rel_path,
                        'type': 'directory',
                        'icon': '📁',
                        'size': 0,
                        'size_formatted': '--'
                    })
        
        files.sort(key=lambda x: (x['type'] != 'directory', x['name'].lower()))
        
        return jsonify({'status': 'success', 'files': files})
    except Exception as e:
        logger.error(f"Files error: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<session_id>/<path:filepath>', methods=['GET'])
def download_file(session_id, filepath):
    try:
        if session_id not in analysis_cache:
            return jsonify({'error': 'Session not found'}), 404
        
        extract_path = get_extract_path(session_id)
        full_path = os.path.join(extract_path, filepath)
        
        if not os.path.abspath(full_path).startswith(os.path.abspath(extract_path)):
            return jsonify({'error': 'Invalid path'}), 403
        
        if not os.path.exists(full_path):
            return jsonify({'error': 'File not found'}), 404
        
        if os.path.isfile(full_path):
            return send_file(full_path, as_attachment=True, download_name=os.path.basename(full_path))
        
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(full_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(full_path))
                    zipf.write(file_path, arcname)
        
        return send_file(temp_zip.name, as_attachment=True, download_name=f"{os.path.basename(filepath)}.zip")
    except Exception as e:
        logger.error(f"Download error: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/download-all/<session_id>', methods=['GET'])
def download_all(session_id):
    try:
        if session_id not in analysis_cache:
            return jsonify({'error': 'Session not found'}), 404
        
        extract_path = get_extract_path(session_id)
        if not os.path.exists(extract_path):
            return jsonify({'error': 'Session expired'}), 404
        
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(extract_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, extract_path)
                    zipf.write(file_path, arcname)
        
        return send_file(temp_zip.name, as_attachment=True, download_name="extracted_apk.zip")
    except Exception as e:
        logger.error(f"Download all error: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/favicon.ico')
def favicon():
    return '', 204  # No content for favicon

# Error handlers
@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 500MB'}), 413

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# Cleanup thread
def cleanup_sessions():
    while True:
        time.sleep(300)
        now = datetime.now()
        expired = [sid for sid, ts in session_timestamps.items() 
                   if (now - ts) > timedelta(seconds=Config.SESSION_TIMEOUT)]
        for sid in expired:
            try:
                apk_path = get_apk_path(sid)
                if os.path.exists(apk_path): os.remove(apk_path)
                extract_path = get_extract_path(sid)
                if os.path.exists(extract_path): shutil.rmtree(extract_path)
                analysis_cache.pop(sid, None)
                session_timestamps.pop(sid, None)
            except: pass
        if expired:
            logger.info(f"Cleaned {len(expired)} sessions")

cleanup_thread = threading.Thread(target=cleanup_sessions, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    logger.info(f"Starting APK Analyzer on port {PORT} (Max upload: {Config.MAX_FILE_SIZE / 1024 / 1024:.0f}MB)")
    app.run(debug=False, host='0.0.0.0', port=PORT, threaded=True)
