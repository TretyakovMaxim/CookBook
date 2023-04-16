import os
from datetime import datetime
from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, current_user, login_required
from flask_ckeditor import upload_fail, upload_success
from werkzeug.urls import url_parse
from werkzeug.utils import send_from_directory
from blog import app, db, photos
from blog.forms import RegistrationForm, LoginForm, EditProfileForm, AddNewRecipe, EmptyForm, \
    ResetPasswordRequestForm, ResetPasswordForm
from blog.models import User, Post
from blog.email import send_password_reset_email


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()


@app.route('/')
@app.route('/home')
@login_required
def index():
    return render_template('index.html', title="CooKBook")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/user/<username>', methods=['GET', 'POST'])
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    if request.method == 'POST' and 'photo' in request.files:
        filename = photos.save(request.files['photo'])
        user.avatar_path = filename
        db.session.commit()
    avatar_path = user.avatar_path
    form = EmptyForm()
    return render_template('user.html', user=user, avatar_path=avatar_path, form=form)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile', form=form)


@app.route('/add_new_recipe', methods=['GET', 'POST'])
@login_required
def add_new_recipe():
    form = AddNewRecipe()
    if request.method == "POST" and form.validate_on_submit():
        name = form.name.data
        body = form.body.data
        post = Post(name=name, body=body, timestamp=datetime.utcnow(), user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_new_recipe.html', form=form)


@app.route('/my_recipes')
@login_required
def my_recipes():
    user = current_user
    recipes = user.posts.all()
    return render_template('my_recipes.html', user=user, recipes=recipes)


@app.route('/recipe/<int:recipe_id>')
@login_required
def recipe_details(recipe_id):
    recipe = Post.query.get_or_404(recipe_id)
    return render_template('recipe_details.html', recipe=recipe)


@app.route('/recipe/<int:recipe_id>/del')
@login_required
def recipe_delete(recipe_id):
    recipe = Post.query.get_or_404(recipe_id)
    db.session.delete(recipe)
    db.session.commit()
    return redirect(url_for('my_recipes'))


@app.route('/files/<path:filename>')
def uploaded_files(filename):
    path = app.config['UPLOADED_PATH']
    return send_from_directory(path, filename, request.environ)


@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('upload')
    extension = f.filename.split('.')[-1].lower()
    if extension not in ['jpg', 'gif', 'png', 'jpeg']:
        return upload_fail(message='Image only!')
    f.save(os.path.join(app.config['UPLOADED_PATH'], f.filename))

    url = url_for('uploaded_files', filename=f.filename)
    return upload_success(url, filename=f.filename)


@app.route('/follow/<username>', methods=['POST'])
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found.'.format(username))
        return redirect(url_for('index'))
    if user == current_user:
        flash('You cannot follow yourself!')
        return redirect(url_for('user', username=username))
    current_user.follow(user)
    db.session.commit()
    flash('You are following {}!'.format(username))
    return redirect(url_for('user', username=username))


@app.route('/unfollow/<username>', methods=['POST'])
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found.'.format(username))
        return redirect(url_for('index'))
    if user == current_user:
        flash('You cannot unfollow yourself!')
        return redirect(url_for('user', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash('You are not following {}.'.format(username))
    return redirect(url_for('user', username=username))


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_request_password.html',
                           title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)
