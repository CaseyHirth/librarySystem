
from flask import render_template, redirect, request, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField, SelectField, SelectMultipleField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from forms import LoginForm, RegisterForm, BookSearchForm, BookAddForm
from app import app, db
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from models import Member, Book, User, Employees



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/book_search_results')
def bookSearchResults():

    isbn = request.args.get('isbn')
    title = request.args.get('title')
    author = request.args.get('author')
    genre = request.args.get('genre')
    branchLocation = request.args.get('branchLocation')

    books = Book.query.filter_by(genre=genre)


    #return '<h1>' + books.first().title + '</h1>'
    return render_template('book_search_results.html', books=books)
    


@app.route('/book_search', methods=['GET', 'POST'])
def search():
    form = BookSearchForm()

    if form.validate_on_submit():
        isbn = form.isbn.data
        title = form.title.data 
        author = form.author.data
        genre = form.genre.data
        branchLocation = form.branchLocation.data 
        return redirect(url_for('bookSearchResults', isbn=isbn, title=title, author=author, genre=genre, branchLocation=branchLocation))

    return render_template('book_search.html', form = form)

@app.route('/add_book', methods=['GET','POST'])
def addBook():
    form = BookAddForm()

    if form.validate_on_submit():
        newBook = Book(isbn=form.isbn.data, title=form.title.data, author=form.author.data, genre=form.genre.data, branchLocation=form.branchLocation.data)
        db.session.add(newBook)
        db.session.commit()


    return render_template('add_book.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
            
        return '<h1>Invalid email or password </h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashedPassword = generate_password_hash(form.password.data, method='sha256')
        newUser = User(email=form.email.data, 
                        password = hashedPassword, 
                        role = 'member')
        newMember = Member(email=form.email.data, 
                    firstName=form.firstName.data, 
                    lastName=form.lastName.data, 
                    gender=form.gender.data, 
                    age=form.age.data,
                    street=form.street.data, 
                    city=form.city.data, 
                    state=form.state.data, 
                    zip=form.zip.data)
        db.session.add(newMember)
        db.session.add(newUser)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + ' ' + form.email.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'member':
        return '<h1>Must be an employee </h1>'
    if current_user.role == 'employee':
        employee = Employees.query.filter_by(email=current_user.email).first()

        return render_template('dashboard.html', name=employee.firstName)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)