from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   ##means from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)
auth.secret_key = "theBois"

@auth.route('/')
def home():
        if 'username' in session:
               return redirect(url_for('base'))
        return redirect(url_for('Login'))



@auth.route('/Login', methods=['GET','POST'])
def login():
        if request.method == 'POST':
                
                username = request.form['Username']
                password = request.form['password']
                user = user.get(username)

                

                if user and check_password_hash(user['password'], password):
                        session['Username'] = username
                        return redirect(url_for('main'))
                else:
                        flash('Invalid username or password')
                        return redirect(url_for('Login'))
        return render_template('Login.html')

@auth.route('/registration', methods=['Get', 'POST'])
def registration():
        if request.method == 'POST':
                email = request.form['email']
                username = request.form['Username']
                password = request.form['password']
                if len(username) <= 3:
                    flash('Username must be greater than 3 characters', category='error')
                elif len(password) < 7:
                       flash('Too short you dingus.', category= 'error') 
                elif len(email) < 4:
                       flash('email must be greater than 4 characters', category='error')
                
        if 'username' in session:
               return render_template('base.html', username=session['Username'])
        return redirect(url_for('Login'))

                       
@auth.route('logout')
def logout():
       session.pop('Username', None)
       return redirect(url_for('Login'))


@auth.route('/base')
def base():
       if 'Username' in session:
              return  render_template('base.html', username=session['Username'])



if __name__ == '__base__':
       auth.run(debug=True)

                
                

        