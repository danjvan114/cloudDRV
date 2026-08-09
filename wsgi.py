from app import app

if __name__ == '__main__':
    try:
        from waitress import serve
        print("Running with Waitress production WSGI server...")
        serve(app, host='0.0.0.0', port=8850, threads=16)
    except ImportError:
        print("Running with Flask development server...")
        app.run(host='0.0.0.0', port=8850)