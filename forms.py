from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField, SelectField, SelectMultipleField
from wtforms.validators import InputRequired, Email, Length  

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(),Email(message='Invalid email')])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')

class RegisterForm(FlaskForm):
    firstName = StringField('First Name', validators=[InputRequired(), Length(min=1, max=50)])
    lastName = StringField('First Name', validators=[InputRequired(), Length(min=1, max=50)])
    age = IntegerField('Age', validators=[InputRequired()])
    gender = SelectField('Gender', choices=[('m','Man'),('w','Woman'), ('nb', 'Non-binary')], validators=[InputRequired()])
    street = StringField('Street Adress', validators=[InputRequired(), Length(min=1, max=50)])
    city = StringField('City', validators=[InputRequired(),Length(min=1, max=50)])
    state = StringField('State', validators=[InputRequired(), Length(min=1, max=50)])
    zip = StringField('Zipcode', validators=[InputRequired(), Length(min=1, max=13)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)]) 
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])

class BookSearchForm(FlaskForm):
    isbn = StringField('ISBN')
    title = StringField('Title', validators=[Length(max=100)])
    author = StringField('Author')
    genre = SelectMultipleField('Genre', choices=[('adventure','Adventure'), ('crime', 'Crime'), ('fantasy', 'Fantasy'), ('horror', 'Horror'), ('memoir', 'Memoir'), ('self-help', 'Self Help')])
    branchLocation = SelectMultipleField('Library Branch', choices=[('pittsburgh', 'Pittsburgh'), ('monroeville', 'Monroeville'), ('cleveland', 'Cleveland'), ('youngstown', 'Youngstown')])

class BookAddForm(FlaskForm):
    isbn = StringField('ISBN', validators=[InputRequired()])
    title = StringField('Title', validators=[Length(max=100)])
    author = StringField('Author', validators=[InputRequired()])
    genre = SelectField('Genre', choices=[('adventure','Adventure'), ('crime', 'Crime'), ('fantasy', 'Fantasy'), ('horror', 'Horror'), ('memoir', 'Memoir'), ('self-help', 'Self Help')], validators=[InputRequired()])
    branchLocation = SelectField('Library Branch', choices=[('pittsburgh', 'Pittsburgh'), ('monroeville', 'Monroeville'), ('cleveland', 'Cleveland'), ('youngstown', 'Youngstown')], validators=[InputRequired()])


