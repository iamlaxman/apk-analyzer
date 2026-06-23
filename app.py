from flask import Flask, request, jsonify, send_file, render_template
from flask_cors import CORS
from flask_compress import Compress
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
from pathlib import Path
import threading
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
Compress(app)  # Enable compression

# ============ Render Configuration ============
# Use environment variables for Render compatibility
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads'))
EXTRACT_FOLDER = os.environ.get('EXTRACT_FOLDER', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'extracted'))
PORT = int(os.environ.get('PORT', 5000))

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(EXTRACT_FOLDER, exist_ok=True)

class Config:
    UPLOAD_FOLDER = UPLOAD_FOLDER
    EXTRACT_FOLDER = EXTRACT_FOLDER
    ALLOWED_EXTENSIONS = {'apk'}
    MAX_FILE_SIZE = 150 * 1024 * 1024  # 150MB for free tier
    SESSION_TIMEOUT = 1800  # 30 minutes on free tier
    MAX_SESSIONS = 20  # Limit sessions for free tier
    MAX_PREVIEW_SIZE = 2 * 1024 * 1024  # 2MB max for preview

app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER
app.config['EXTRACT_FOLDER'] = Config.EXTRACT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_FILE_SIZE

# Store analysis results
analysis_cache = {}
session_timestamps = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def get_session_id():
    return hashlib.sha256(os.urandom(32)).hexdigest()[:16]

def get_extract_path(session_id):
    return os.path.join(app.config['EXTRACT_FOLDER'], session_id)

def get_apk_path(session_id):
    return os.path.join(app.config['UPLOAD_FOLDER'], f"{session_id}.apk")

def format_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"

def get_file_icon(filename):
    ext = os.path.splitext(filename)[1].lower()
    icons = {
        '.dex': '📦', '.xml': '📋', '.png': '🖼️', '.jpg': '🖼️',
        '.json': '📊', '.so': '⚙️', '.js': '📜', '.html': '🌐',
        '.css': '🎨', '.kt': '🔷', '.java': '☕', '.txt': '📄',
        '.arsc': '📚', '.pro': '🔒', '.sf': '✍️', '.rsa': '🔑',
        '.mp3': '🎵', '.mp4': '🎬', '.ttf': '🔤', '.otf': '🔤'
    }
    return icons.get(ext, '📄')

def analyze_apk_structure(extract_path, apk_path):
    """Comprehensive APK analysis"""
    analysis = {
        'basic_info': {
            'package_name': 'Unknown',
            'version_name': 'Unknown',
            'version_code': 'Unknown',
            'min_sdk': 'Unknown',
            'target_sdk': 'Unknown',
            'app_name': 'Unknown'
        },
        'permissions': [],
        'components': {
            'activities': [],
            'services': [],
            'receivers': [],
            'providers': []
        },
        'tech_stack': {'languages': [], 'frameworks': [], 'libraries': []},
        'dex_analysis': {'total_classes': 0, 'total_methods': 0, 'dex_files': []},
        'security': [],
        'file_structure': [],
        'certificate': None,
        'total_size': os.path.getsize(apk_path) if os.path.exists(apk_path) else 0
    }
    
    # Parse manifest
    manifest_path = os.path.join(extract_path, 'AndroidManifest.xml')
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, 'rb') as f:
                content = f.read()
                text = content.decode('latin-1', errors='ignore')
                
                # Extract package
                pkg_match = re.search(r'package="([^"]+)"', text)
                if pkg_match:
                    analysis['basic_info']['package_name'] = pkg_match.group(1)
                
                # Extract version
                ver_match = re.search(r'versionName="([^"]+)"', text)
                if ver_match:
                    analysis['basic_info']['version_name'] = ver_match.group(1)
                
                code_match = re.search(r'versionCode="(\d+)"', text)
                if code_match:
                    analysis['basic_info']['version_code'] = code_match.group(1)
                
                # Extract SDK versions
                min_match = re.search(r'minSdkVersion="(\d+)"', text)
                if min_match:
                    analysis['basic_info']['min_sdk'] = min_match.group(1)
                
                target_match = re.search(r'targetSdkVersion="(\d+)"', text)
                if target_match:
                    analysis['basic_info']['target_sdk'] = target_match.group(1)
                
                # Extract permissions
                permissions = re.findall(r'uses-permission.*?android:name="([^"]+)"', text)
                analysis['permissions'] = permissions
                
                # Extract components
                activities = re.findall(r'<activity.*?android:name="([^"]+)"', text)
                analysis['components']['activities'] = activities
                
                services = re.findall(r'<service.*?android:name="([^"]+)"', text)
                analysis['components']['services'] = services
                
                receivers = re.findall(r'<receiver.*?android:name="([^"]+)"', text)
                analysis['components']['receivers'] = receivers
                
                providers = re.findall(r'<provider.*?android:name="([^"]+)"', text)
                analysis['components']['providers'] = providers
                
                # Security checks
                if 'android:debuggable="true"' in text:
                    analysis['security'].append({
                        'type': 'debuggable',
                        'severity': 'high',
                        'description': 'Application is debuggable - this should not be enabled in production'
                    })
                
                if 'android:allowBackup="true"' in text:
                    analysis['security'].append({
                        'type': 'allow_backup',
                        'severity': 'medium',
                        'description': 'Application allows backup - user data can be extracted via ADB'
                    })
                
                if 'android:exported="true"' in text:
                    analysis['security'].append({
                        'type': 'exported_components',
                        'severity': 'medium',
                        'description': 'Application has exported components that other apps can access'
                    })
                
                dangerous_perms = ['SMS', 'LOCATION', 'CAMERA', 'CONTACTS', 'PHONE', 'MICROPHONE', 'CALL_LOG']
                for perm in permissions:
                    for dangerous in dangerous_perms:
                        if dangerous in perm.upper():
                            analysis['security'].append({
                                'type': 'dangerous_permission',
                                'severity': 'medium',
                                'description': f'Dangerous permission requested: {perm}'
                            })
                            break
        except Exception as e:
            logger.error(f"Error parsing manifest: {e}")
            analysis['errors'] = [str(e)]
    
    # Analyze DEX files
    for file in os.listdir(extract_path):
        if file.endswith('.dex'):
            filepath = os.path.join(extract_path, file)
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()
                    # Count class references
                    classes = re.findall(b'Ljava/([^;]+);', data)
                    unique_classes = list(set(classes))[:100]  # Limit to 100 classes
                    
                    analysis['dex_analysis']['dex_files'].append({
                        'name': file,
                        'size': os.path.getsize(filepath),
                        'class_count': len(unique_classes),
                        'method_count': len(re.findall(b'\x00\x00\x00\x00', data[:10000])),  # Sample first 10KB
                        'classes': [c.decode('utf-8', errors='ignore').replace('/', '.') for c in unique_classes]
                    })
                    
                    analysis['dex_analysis']['total_classes'] += len(unique_classes)
                    analysis['dex_analysis']['total_methods'] += len(re.findall(b'\x00\x00\x00\x00', data[:10000]))
            except Exception as e:
                logger.error(f"Error analyzing DEX file {file}: {e}")
    
    # Detect tech stack
    lib_path = os.path.join(extract_path, 'lib')
    if os.path.exists(lib_path):
        analysis['tech_stack']['languages'].append('C/C++ (Native)')
        for arch in os.listdir(lib_path):
            arch_path = os.path.join(lib_path, arch)
            if os.path.isdir(arch_path):
                for lib in os.listdir(arch_path):
                    lib_lower = lib.lower()
                    if 'flutter' in lib_lower:
                        if 'Flutter' not in analysis['tech_stack']['frameworks']:
                            analysis['tech_stack']['frameworks'].append('Flutter')
                    elif 'react' in lib_lower or 'hermes' in lib_lower:
                        if 'React Native' not in analysis['tech_stack']['frameworks']:
                            analysis['tech_stack']['frameworks'].append('React Native')
                    elif 'xamarin' in lib_lower:
                        if 'Xamarin' not in analysis['tech_stack']['frameworks']:
                            analysis['tech_stack']['frameworks'].append('Xamarin')
                    elif 'unity' in lib_lower:
                        if 'Unity' not in analysis['tech_stack']['frameworks']:
                            analysis['tech_stack']['frameworks'].append('Unity')
    
    # Check for Kotlin
    for root, dirs, files in os.walk(extract_path):
        if any(f.endswith('.kotlin_module') for f in files):
            analysis['tech_stack']['languages'].append('Kotlin')
            break
    
    # Check for common libraries
    assets_path = os.path.join(extract_path, 'assets')
    if os.path.exists(assets_path):
        for root, dirs, files in os.walk(assets_path):
            for file in files:
                f_lower = file.lower()
                if 'firebase' in f_lower:
                    if 'Firebase' not in analysis['tech_stack']['libraries']:
                        analysis['tech_stack']['libraries'].append('Firebase')
                elif 'glide' in f_lower:
                    if 'Glide' not in analysis['tech_stack']['libraries']:
                        analysis['tech_stack']['libraries'].append('Glide')
                elif 'okhttp' in f_lower or 'retrofit' in f_lower:
                    if 'OkHttp/Retrofit' not in analysis['tech_stack']['libraries']:
                        analysis['tech_stack']['libraries'].append('OkHttp/Retrofit')
                elif 'gson' in f_lower:
                    if 'Gson' not in analysis['tech_stack']['libraries']:
                        analysis['tech_stack']['libraries'].append('Gson')
                elif 'room' in f_lower:
                    if 'Room' not in analysis['tech_stack']['libraries']:
                        analysis['tech_stack']['libraries'].append('Room')
    
    # Build file structure (limit depth for performance)
    def walk_directory(path, level=0, max_level=3):
        if level > max_level:
            return []
        
        items = []
        try:
            for item in sorted(os.listdir(path)):
                full_path = os.path.join(path, item)
                rel_path = os.path.relpath(full_path, extract_path).replace('\\', '/')
                
                if os.path.isfile(full_path):
                    items.append({
                        'name': item,
                        'path': rel_path,
                        'type': 'file',
                        'size': os.path.getsize(full_path),
                        'size_formatted': format_size(os.path.getsize(full_path)),
                        'extension': os.path.splitext(item)[1].lower(),
                        'icon': get_file_icon(item),
                        'mime': mimetypes.guess_type(item)[0] or 'application/octet-stream'
                    })
                elif os.path.isdir(full_path):
                    items.append({
                        'name': item,
                        'path': rel_path,
                        'type': 'directory',
                        'icon': '📁',
                        'children': walk_directory(full_path, level + 1, max_level)
                    })
        except PermissionError:
            pass
        return items
    
    analysis['file_structure'] = walk_directory(extract_path)
    
    if not analysis['tech_stack']['languages']:
        analysis['tech_stack']['languages'].append('Java')
    
    return analysis

# ============ Routes ============

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    """Health check endpoint for Render"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'sessions': len(analysis_cache),
        'version': '1.0.0'
    })

@app.route('/api/upload', methods=['POST'])
def upload_apk():
    # Check session limit
    if len(analysis_cache) >= Config.MAX_SESSIONS:
        # Clean old sessions
        cleanup_old_sessions()
        if len(analysis_cache) >= Config.MAX_SESSIONS:
            return jsonify({'error': 'Server busy. Please try again later.'}), 429
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only APK files allowed'}), 400
    
    try:
        session_id = get_session_id()
        filename = secure_filename(file.filename)
        apk_path = get_apk_path(session_id)
        file.save(apk_path)
        
        # Check file size after saving
        if os.path.getsize(apk_path) > Config.MAX_FILE_SIZE:
            os.remove(apk_path)
            return jsonify({'error': f'File too large. Maximum size is {format_size(Config.MAX_FILE_SIZE)}'}), 413
        
        extract_path = get_extract_path(session_id)
        os.makedirs(extract_path, exist_ok=True)
        
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        
        analysis = analyze_apk_structure(extract_path, apk_path)
        analysis_cache[session_id] = analysis
        session_timestamps[session_id] = datetime.now()
        
        logger.info(f"Successfully processed APK: {filename} (Session: {session_id})")
        
        return jsonify({
            'status': 'success',
            'session_id': session_id,
            'filename': filename,
            'message': 'APK uploaded and analyzed successfully'
        })
        
    except zipfile.BadZipFile:
        return jsonify({'error': 'Invalid APK file - not a valid ZIP archive'}), 400
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/analyze/<session_id>', methods=['GET'])
def get_analysis(session_id):
    if session_id not in analysis_cache:
        return jsonify({'error': 'Session not found or expired'}), 404
    
    # Update timestamp
    session_timestamps[session_id] = datetime.now()
    
    return jsonify({
        'status': 'success',
        'analysis': analysis_cache[session_id]
    })

@app.route('/api/files/<session_id>', methods=['GET'])
def get_files(session_id):
    if session_id not in analysis_cache:
        return jsonify({'error': 'Session not found or expired'}), 404
    
    path = request.args.get('path', '')
    extract_path = get_extract_path(session_id)
    
    if not os.path.exists(extract_path):
        return jsonify({'error': 'Session files not found'}), 404
    
    current_path = os.path.join(extract_path, path) if path else extract_path
    
    # Security: prevent directory traversal
    if not os.path.abspath(current_path).startswith(os.path.abspath(extract_path)):
        return jsonify({'error': 'Invalid path'}), 403
    
    if not os.path.exists(current_path):
        return jsonify({'error': 'Path not found'}), 404
    
    files = []
    if os.path.isfile(current_path):
        file_info = {
            'name': os.path.basename(current_path),
            'path': path,
            'type': 'file',
            'size': os.path.getsize(current_path),
            'size_formatted': format_size(os.path.getsize(current_path)),
            'icon': get_file_icon(os.path.basename(current_path)),
            'mime': mimetypes.guess_type(current_path)[0] or 'application/octet-stream',
            'extension': os.path.splitext(current_path)[1].lower()
        }
        files.append(file_info)
    else:
        try:
            for item in sorted(os.listdir(current_path)):
                full_path = os.path.join(current_path, item)
                rel_path = os.path.relpath(full_path, extract_path).replace('\\', '/')
                
                if os.path.isfile(full_path):
                    files.append({
                        'name': item,
                        'path': rel_path,
                        'type': 'file',
                        'size': os.path.getsize(full_path),
                        'size_formatted': format_size(os.path.getsize(full_path)),
                        'icon': get_file_icon(item),
                        'mime': mimetypes.guess_type(item)[0] or 'application/octet-stream',
                        'extension': os.path.splitext(item)[1].lower()
                    })
                elif os.path.isdir(full_path):
                    files.append({
                        'name': item,
                        'path': rel_path,
                        'type': 'directory',
                        'icon': '📁',
                        'size': 0,
                        'size_formatted': '--'
                    })
        except PermissionError:
            return jsonify({'error': 'Permission denied'}), 403
    
    files.sort(key=lambda x: (x['type'] != 'directory', x['name'].lower()))
    
    return jsonify({
        'status': 'success',
        'current_path': path,
        'files': files
    })

@app.route('/api/file-content/<session_id>', methods=['GET'])
def get_file_content(session_id):
    if session_id not in analysis_cache:
        return jsonify({'error': 'Session not found or expired'}), 404
    
    filepath = request.args.get('path', '')
    extract_path = get_extract_path(session_id)
    
    if not filepath:
        return jsonify({'error': 'No path provided'}), 400
    
    full_path = os.path.join(extract_path, filepath)
    
    # Security check
    if not os.path.abspath(full_path).startswith(os.path.abspath(extract_path)):
        return jsonify({'error': 'Invalid path'}), 403
    
    if not os.path.exists(full_path) or not os.path.isfile(full_path):
        return jsonify({'error': 'File not found'}), 404
    
    # Check file size for preview
    file_size = os.path.getsize(full_path)
    if file_size > Config.MAX_PREVIEW_SIZE:
        return jsonify({
            'status': 'success',
            'preview': False,
            'message': f'File too large for preview ({format_size(file_size)}). Please download instead.',
            'size': format_size(file_size)
        })
    
    extension = os.path.splitext(filepath)[1].lower()
    preview_types = {
        '.xml': 'xml', '.txt': 'text', '.json': 'json',
        '.smali': 'smali', '.java': 'java', '.kt': 'kotlin',
        '.js': 'javascript', '.html': 'html', '.css': 'css',
        '.py': 'python', '.md': 'markdown', '.yml': 'yaml',
        '.yaml': 'yaml', '.gradle': 'groovy', '.properties': 'properties',
        '.pro': 'text', '.cfg': 'text', '.ini': 'text',
        '.sh': 'bash', '.bat': 'batch', '.ps1': 'powershell'
    }
    
    if extension in preview_types:
        try:
            # Try multiple encodings
            for encoding in ['utf-8', 'latin-1', 'cp1252']:
                try:
                    with open(full_path, 'r', encoding=encoding) as f:
                        content = f.read(50000)  # Limit to 50KB for preview
                    break
                except UnicodeDecodeError:
                    continue
            
            return jsonify({
                'status': 'success',
                'preview': True,
                'type': preview_types.get(extension, 'text'),
                'content': content,
                'size': format_size(file_size)
            })
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {e}")
    
    return jsonify({
        'status': 'success',
        'preview': False,
        'message': 'Binary file - preview not available',
        'size': format_size(file_size)
    })

@app.route('/api/download/<session_id>/<path:filepath>', methods=['GET'])
def download_file(session_id, filepath):
    if session_id not in analysis_cache:
        return jsonify({'error': 'Session not found or expired'}), 404
    
    extract_path = get_extract_path(session_id)
    full_path = os.path.join(extract_path, filepath)
    
    # Security check
    if not os.path.abspath(full_path).startswith(os.path.abspath(extract_path)):
        return jsonify({'error': 'Invalid path'}), 403
    
    if not os.path.exists(full_path):
        return jsonify({'error': 'File not found'}), 404
    
    if os.path.isfile(full_path):
        return send_file(
            full_path,
            as_attachment=True,
            download_name=os.path.basename(full_path),
            mimetype=mimetypes.guess_type(full_path)[0] or 'application/octet-stream'
        )
    
    # Create ZIP for directories
    try:
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(full_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(full_path))
                    zipf.write(file_path, arcname)
        
        return send_file(
            temp_zip.name,
            as_attachment=True,
            download_name=f"{os.path.basename(filepath)}.zip",
            mimetype='application/zip'
        )
    except Exception as e:
        logger.error(f"Error creating ZIP: {e}")
        return jsonify({'error': 'Failed to create ZIP file'}), 500

@app.route('/api/download-all/<session_id>', methods=['GET'])
def download_all(session_id):
    if session_id not in analysis_cache:
        return jsonify({'error': 'Session not found or expired'}), 404
    
    extract_path = get_extract_path(session_id)
    
    if not os.path.exists(extract_path):
        return jsonify({'error': 'Session files not found'}), 404
    
    apk_path = get_apk_path(session_id)
    base_name = os.path.splitext(os.path.basename(apk_path))[0] if os.path.exists(apk_path) else 'extracted'
    
    try:
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(extract_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, extract_path)
                    zipf.write(file_path, arcname)
        
        return send_file(
            temp_zip.name,
            as_attachment=True,
            download_name=f"{base_name}_extracted.zip",
            mimetype='application/zip'
        )
    except Exception as e:
        logger.error(f"Error creating full ZIP: {e}")
        return jsonify({'error': 'Failed to create ZIP file'}), 500

@app.route('/api/manifest/<session_id>', methods=['GET'])
def get_manifest(session_id):
    if session_id not in analysis_cache:
        return jsonify({'error': 'Session not found or expired'}), 404
    
    extract_path = get_extract_path(session_id)
    manifest_path = os.path.join(extract_path, 'AndroidManifest.xml')
    
    if not os.path.exists(manifest_path):
        return jsonify({'error': 'Manifest not found'}), 404
    
    try:
        with open(manifest_path, 'rb') as f:
            content = f.read()
            text = content.decode('utf-8', errors='replace')
        
        return jsonify({
            'status': 'success',
            'manifest': text
        })
    except Exception as e:
        logger.error(f"Error reading manifest: {e}")
        return jsonify({'error': 'Failed to read manifest'}), 500

@app.route('/api/export-report/<session_id>', methods=['GET'])
def export_report(session_id):
    if session_id not in analysis_cache:
        return jsonify({'error': 'No analysis found'}), 404
    
    report = analysis_cache[session_id]
    
    try:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json', mode='w')
        json.dump(report, temp_file, indent=2, default=str)
        temp_file.close()
        
        return send_file(
            temp_file.name,
            as_attachment=True,
            download_name=f"apk_analysis_report.json",
            mimetype='application/json'
        )
    except Exception as e:
        logger.error(f"Error exporting report: {e}")
        return jsonify({'error': 'Failed to export report'}), 500

# ============ Session Management ============

def cleanup_old_sessions():
    """Remove expired sessions"""
    now = datetime.now()
    expired = []
    
    for session_id, timestamp in session_timestamps.items():
        if (now - timestamp) > timedelta(seconds=Config.SESSION_TIMEOUT):
            expired.append(session_id)
    
    for session_id in expired:
        try:
            apk_path = get_apk_path(session_id)
            if os.path.exists(apk_path):
                os.remove(apk_path)
            
            extract_path = get_extract_path(session_id)
            if os.path.exists(extract_path):
                shutil.rmtree(extract_path)
            
            if session_id in analysis_cache:
                del analysis_cache[session_id]
            if session_id in session_timestamps:
                del session_timestamps[session_id]
        except Exception as e:
            logger.error(f"Error cleaning session {session_id}: {e}")
    
    if expired:
        logger.info(f"Cleaned {len(expired)} expired sessions")

def background_cleanup():
    """Background thread for periodic cleanup"""
    while True:
        time.sleep(300)  # Run every 5 minutes
        cleanup_old_sessions()

# Start background cleanup
cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
cleanup_thread.start()

# Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(413)
def too_large_error(error):
    return jsonify({'error': 'File too large'}), 413

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# ============ Main ============
if __name__ == '__main__':
    # For local development
    logger.info(f"Starting APK Analyzer on port {PORT}")
    logger.info(f"Upload folder: {UPLOAD_FOLDER}")
    logger.info(f"Extract folder: {EXTRACT_FOLDER}")
    app.run(debug=False, host='0.0.0.0', port=PORT, threaded=True)