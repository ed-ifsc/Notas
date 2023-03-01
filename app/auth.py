from flask import Blueprint
from flask import request, render_template, url_for, redirect, flash
from werkzeug.security import generate_password_hash
from .models import User
from app import db

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return '<h1>Login</h1>'


@auth.route('/logout')
def logout():
    return '<h1>Logout</h1>'


@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email já existe.', category='error')
        elif len(email) < 4:
            flash('Email deve ter mais de 3 caracteres.', category='error')
        elif len(first_name) < 2:
            flash('O nome deve ter mais de 1 caracter.', category='error')
        elif password1 != password2:
            flash('Senhas não conferem.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:

            new_user = User(email=email, first_name=first_name,
                            password=generate_password_hash(password1,
                                                            method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('Conta criada!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html")

