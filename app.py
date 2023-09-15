# app.py

import os
from flask import Flask, render_template, request, redirect, url_for, current_app, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, SubmitField, validators, TextAreaField, DecimalField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from flask_uploads import UploadSet, configure_uploads
from email_validator import validate_email, EmailNotValidError
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

from sqlalchemy.sql import func

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = ':hp7weDA\DW(<NaM!<83%buX'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50))

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    instructor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_filename = db.Column(db.String(255))
    price = db.Column(db.Float(precision=2))

    instructor = db.relationship('User', backref='instructor_courses', foreign_keys=[instructor_id], lazy=True)
    videos = db.relationship('Video', backref='course', lazy=True)
    subscriptions = db.relationship('Subscription', backref='course', lazy=True)
    categories = db.relationship('CategoryTag', secondary='course_category', backref='courses', lazy=True)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    video_url = db.Column(db.Text)  # Or an appropriate data type for video URLs
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)

class ProgressTracking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'))
    timestamp = db.Column(db.TIMESTAMP)

class CommentRating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'))
    comment_text = db.Column(db.Text)
    rating = db.Column(db.Integer)

class Instructor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    bio = db.Column(db.Text)
    contact_info = db.Column(db.Text)

class CategoryTag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)

class CourseCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('category_tag.id'))

class VideoTag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('category_tag.id'))



class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        validators.DataRequired(),
        validators.Length(min=3, max=50, message="Username must be between 3 and 50 characters."),
    ])
    email = StringField('Email', validators=[
        validators.DataRequired(),
        validators.Email(message="Invalid email address."),
    ])
    password = PasswordField('Password', validators=[
        validators.DataRequired(),
        validators.Length(min=8, message="Password must be at least 8 characters long."),
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        validators.DataRequired(),
        validators.EqualTo('password', message="Passwords must match."),
    ])
    role = SelectField('Role', choices=[('student', 'Student'), ('instructor', 'Instructor')], validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        validators.DataRequired(),
    ])
    password = PasswordField('Password', validators=[
        validators.DataRequired(),
    ])
    submit = SubmitField('Login')


class CourseCreationForm(FlaskForm):
    title = StringField('Course Title', validators=[DataRequired(), Length(min=5, max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=10)])
    price = DecimalField('Price (#)', validators=[DataRequired(), NumberRange(min=0.01)])
    image = FileField('Course Image', validators=[FileRequired()])
    category = SelectField('Category', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Create Course')

class CategoryCreationForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired()])
    submit = SubmitField('Create Category')


# Route for the home page
@app.route('/')
def home():
    return render_template('index.html')

# Route for the dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Route for the register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        role = form.role.data  # Get the selected role

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists. Please choose another.', 'danger')
        else:
            # Create a new user with the selected role and hash the password
            new_user = User(username=username, email=email, password_hash=generate_password_hash(password), role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html', form=form)


# Create the login manager to laod user from the database
@login_manager.user_loader
def load_user(user_id):
    # Load the user object from the database based on user_id
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))  # Redirect logged-in users to the dashboard

    # Create an instance of the LoginForm
    form = LoginForm()

    if form.validate_on_submit():
        # Form validation passed
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')

    # If the form is not submitted or validation failed, render the login form
    return render_template('login.html', form=form)

# implement route for logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

# Route for creating a new course
# Define the allowed file extensions for image uploads
#images = UploadSet("images", IMAGES)

# Configure the upload set
# configure_uploads(app, images)
# Define allowed images extensions
# ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
# @app.route('/create_course', methods=['GET', 'POST'])
# @login_required     # Ensure only authenticated instructors can create courses
# def create_course():
#     if current_user.role != 'instructor':
#         flash('You do not have permission to create courses.', 'danger')
#         return redirect(url_for('dashboard'))

#     form = CourseCreationForm()

#     if form.validate_on_submit():
#         # Handle image upload
#         image = form.image.data
#         if image:
#             filename = secure_filename(image.filename)
            
#             # Check if the file extension is allowed
#             if '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS:
#                 image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'course-images', filename)
#                 image.save(image_path)
#             else:
#                 flash('Invalid image file format. Allowed formats: jpg, jpeg, png, gif', 'danger')
#                 return redirect(url_for('create_course'))

#         # Create a new course and save it to the database
#         new_course = Course(
#             title=form.title.data,
#             description=form.description.data,
#             instructor_id=current_user.id,
#             price=form.price.data,
#             image_filename=filename if image else None  # Store the filename in the Course model
#         )
#         db.session.add(new_course)
#         db.session.commit()
#         flash('Course created successfully.', 'success')
#         return redirect(url_for('dashboard'))

#     return render_template('create_course.html', form=form)

# Define a route to handle the category creation form submission
@app.route('/create_category', methods=['GET', 'POST'])
@login_required
def create_category():
    if current_user.role != 'instructor':
        flash('You do not have permission to create category.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = CategoryCreationForm()

    if form.validate_on_submit():
        # create a new category and save it in the database
        new_category = CategoryTag(name=form.name.data)
        db.session.add(new_category)
        db.session.commit()
        flash('Category ccreated successfully')
        return redirect(url_for('dashboard'))
    
    return render_template('create_category.html', form=form)

# Create course route
# Define allowed images extensions
ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
@app.route('/create_course', methods=['GET', 'POST'])
@login_required
def create_course():
    if current_user.role != 'instructor':
        flash('You do not have permission to create courses.', 'danger')
        return redirect(url_for('dashboard'))
    
    form = CourseCreationForm()

    # Fetch categories from the database
    categories = CategoryTag.query.all()
    # Populate the category choices for the select field
    form.category.choices = [(category.id, category.name) for category in categories]

    if form.validate_on_submit():
        # Handle image upload
        image = form.image.data
        if image:
            filename = secure_filename(image.filename)
            
            # Check if the file extension is allowed
            if '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'course-images', filename)
                image.save(image_path)
            else:
                flash('Invalid image file format. Allowed formats: jpg, jpeg, png, gif', 'danger')
                return redirect(url_for('create_course'))

        # Create a new course and save it to the database
        new_course = Course(
            title=form.title.data,
            description=form.description.data,
            instructor_id=current_user.id,
            price=form.price.data,
            image_filename=filename if image else None  # Store the filename in the Course model
        )
        db.session.add(new_course)
        db.session.commit()
        flash('Course created successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_course.html', form=form)


# Route view all courses
@app.route('/courses')
def courses():
    return render_template('courses.html')





if __name__ == '__main__':
    app.run(debug=True)
