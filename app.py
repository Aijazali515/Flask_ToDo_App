from __future__ import annotations
import os
from datetime import datetime
from typing import Optional

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import generate_csrf
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional as OptionalValidator
from sqlalchemy import or_

# -----------------------------------------------------------------------------
# App and Config
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///todo.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tasks = db.relationship('Task', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)  # Active = pending, Inactive = done
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

# -----------------------------------------------------------------------------
# Forms
# -----------------------------------------------------------------------------
class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=128)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Create account')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField('Sign in')


class TaskForm(FlaskForm):
    id = HiddenField()  # for edit
    title = StringField('Title', validators=[DataRequired(), Length(max=120)])
    description = TextAreaField('Description', validators=[OptionalValidator(), Length(max=2000)])
    due_date = DateField('Due Date', validators=[OptionalValidator()], format='%Y-%m-%d')
    is_active = BooleanField('Active (Pending)')
    submit = SubmitField('Save')


# -----------------------------------------------------------------------------
# Login loader
# -----------------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return db.session.get(User, int(user_id))


# -----------------------------------------------------------------------------
# Routes: Auth
# -----------------------------------------------------------------------------
@app.context_processor
def inject_csrf():
    # Allows using {{ csrf_token() }} in any template and JS exposure
    return dict(csrf_token=generate_csrf)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash('Email already registered', 'warning')
            return redirect(url_for('register'))
        user = User(email=form.email.data.lower())
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please sign in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if not user or not user.check_password(form.password.data):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember.data)
        return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been signed out.', 'info')
    return redirect(url_for('login'))


# -----------------------------------------------------------------------------
# Routes: Dashboard and Tasks
# -----------------------------------------------------------------------------
@app.route('/')
@login_required
def dashboard():
    # Filters
    q = request.args.get('q', '', type=str)
    sort = request.args.get('sort', 'created_desc', type=str)
    status = request.args.get('status', 'all', type=str)  # all|active|inactive

    query = Task.query.filter_by(user_id=current_user.id)

    if q:
        like = f"%{q}%"
        query = query.filter(or_(Task.title.ilike(like), Task.description.ilike(like)))

    if status == 'active':
        query = query.filter_by(is_active=True)
    elif status == 'inactive':
        query = query.filter_by(is_active=False)

    # Sorting
    if sort == 'due_asc':
        query = query.order_by(Task.due_date.asc().nulls_last())
    elif sort == 'due_desc':
        query = query.order_by(Task.due_date.desc().nulls_last())
    elif sort == 'title_asc':
        query = query.order_by(Task.title.asc())
    elif sort == 'title_desc':
        query = query.order_by(Task.title.desc())
    elif sort == 'updated_desc':
        query = query.order_by(Task.updated_at.desc())
    else:  # created_desc
        query = query.order_by(Task.created_at.desc())

    tasks = query.all()

    stats = {
        'total': Task.query.filter_by(user_id=current_user.id).count(),
        'active': Task.query.filter_by(user_id=current_user.id, is_active=True).count(),
        'inactive': Task.query.filter_by(user_id=current_user.id, is_active=False).count(),
    }

    return render_template('dashboard.html', tasks=tasks, q=q, sort=sort, status=status, stats=stats)


@app.route('/task/new', methods=['GET', 'POST'])
@login_required
def task_new():
    form = TaskForm()
    if form.validate_on_submit():
        task = Task(
            user_id=current_user.id,
            title=form.title.data,
            description=form.description.data,
            due_date=form.due_date.data,
            is_active=form.is_active.data if form.is_active.data is not None else True,
        )
        db.session.add(task)
        db.session.commit()
        flash('Task added.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('task_form.html', form=form, mode='new')


@app.route('/task/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def task_edit(task_id: int):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    form = TaskForm(obj=task)
    if form.validate_on_submit():
        task.title = form.title.data
        task.description = form.description.data
        task.due_date = form.due_date.data
        task.is_active = form.is_active.data
        db.session.commit()
        flash('Task updated.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('task_form.html', form=form, mode='edit', task=task)


@app.route('/task/<int:task_id>/delete', methods=['POST'])
@login_required
def task_delete(task_id: int):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted.', 'info')
    if request.accept_mimetypes.best == 'application/json' or request.is_json:
        return jsonify({'ok': True})
    return redirect(url_for('dashboard'))


@app.route('/task/<int:task_id>/toggle', methods=['POST'])
@login_required
def task_toggle(task_id: int):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    task.is_active = not task.is_active
    db.session.commit()
    # Return updated status for AJAX toggle
    if request.accept_mimetypes.best == 'application/json' or request.is_json:
        return jsonify({'ok': True, 'is_active': task.is_active})
    return redirect(url_for('dashboard'))


# -----------------------------------------------------------------------------
# CLI and App start
# -----------------------------------------------------------------------------
@app.cli.command('init-db')
def init_db_command():
    """Initialize the database."""
    db.create_all()
    print('Initialized the database.')


if __name__ == '__main__':
    # For Windows dev convenience
    port = int(os.environ.get('PORT', 5000))
    # Ensure database tables exist on startup
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', port=port, debug=True)
  
