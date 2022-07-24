from flask import render_template, session, url_for, redirect
from app.appsetup import app
from app.appsetup import LOG

@app.route('/', methods=['GET'])
def index():
    response = redirect(url_for("accounts"))
    return response
