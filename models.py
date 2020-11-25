from app import app, db, login_manager
from flask_login import UserMixin

class Member(UserMixin, db.Model):

    __tablename__ = 'members'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email=db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    firstName = db.Column(db.String(50))
    lastName = db.Column(db.String(50))
    age = db.Column(db.Integer)
    gender = db.Column(db.String(5))
    street = db.Column(db.String(50))
    city = db.Column(db.String(50))
    state = db.Column(db.String(50))
    zip = db.Column(db.String(13))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    isAdmin = db.Column(db.Boolean, default=True)

@login_manager.user_loader
def load_user(user_id):
    return Member.query.get(int(user_id))


#class Employees(db.Model):



class Book(db.Model):

    __tablename__ = 'books'

    id = db.Column(db.Integer, primary_key=True)
    isbn = db.Column(db.String(15))
    title = db.Column(db.String(50))
    author = db.Column(db.String(50))
    genre = db.Column(db.String(50))
    branchLocation = db.Column(db.String(50))


    