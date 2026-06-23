import os
import sys

# Check if required packages are installed
try:
    from flask import Flask
    from flask_cors import CORS
except ImportError as e:
    print("=" * 50)
    print("ERROR: Required packages are not installed!")
    print("=" * 50)
    print("\nPlease run the following command:")
    print("pip install flask flask-cors werkzeug")
    print("\nOr use the setup.bat file to install automatically.")
    print("=" * 50)
    sys.exit(1)

# Try to import the main app
try:
    # Try the full version first
    from app import app
    print("Using full version with Androguard")
except ImportError:
    try:
        # Fall back to simple version
        from app_simple import app
        print("Using simplified version (Androguard not available)")
    except ImportError:
        print("Error: Could not find app.py or app_simple.py")
        sys.exit(1)

if __name__ == '__main__':
    print("\n" + "=" * 50)
    print("APK Analyzer Server Starting...")
    print("=" * 50)
    print(f"\nOpen your browser and go to: http://localhost:5000")
    print("\nPress Ctrl+C to stop the server\n")
    print("=" * 50 + "\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)