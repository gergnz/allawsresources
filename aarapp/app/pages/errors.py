from flask import render_template, jsonify
from app.appsetup import app

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html', error=str(error)), 403

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html', error=str(error)), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('405.html', error=str(error)), 405
