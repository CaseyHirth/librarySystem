from app import app, db, login_manager
from flask_login import UserMixin
from datetime import date, timedelta

class User(UserMixin, db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    role = db.Column(db.String(30))

class Member(db.Model):

    __tablename__ = 'members'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email=db.Column(db.String(50), unique=True)
    firstName = db.Column(db.String(50))
    lastName = db.Column(db.String(50))
    memberSince = db.Column(db.DateTime, default=date.today())
    age = db.Column(db.Integer)
    gender = db.Column(db.String(5))
    street = db.Column(db.String(50))
    city = db.Column(db.String(50))
    state = db.Column(db.String(50))
    zip = db.Column(db.String(13))
   
    checkOuts = db.relationship('CheckOut', backref='borrower')
    check_in = db.relationship('CheckIn', backref='borrower')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Employees(db.Model):

    __tablename__ = "employees"

    id = db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(50), unique=True)
    firstName = db.Column(db.String(50))
    lastName = db.Column(db.String(50))
    job_id = db.Column('job_id', db.Integer, db.ForeignKey('jobs.id'))
    street = db.Column(db.String(50))
    state = db.Column(db.String(50))
    city = db.Column(db.String(50))
    zip = db.Column(db.String(50))

    branchManager = db.relationship('Branch', backref='manager')
    regionManager = db.relationship('Region', backref='region_manager')


class Job(db.Model):
    __tablename__ = "jobs"
    
    id = db.Column(db.Integer, primary_key=True)
    job_title = db.Column(db.String(50))
    job_description = db.Column(db.String(200))

    employess = db.relationship('Employees', backref='employees')


class Book(db.Model):

    __tablename__ = 'books'

    id = db.Column(db.Integer, primary_key=True)
    isbn = db.Column(db.String(15))
    title = db.Column(db.String(50))
    author = db.Column(db.String(50))
    genre = db.Column(db.String(50))
    branchLocation = db.Column(db.String(50))


    check_out = db.relationship('CheckOut', backref='borrowed_book')
    check_in = db.relationship('CheckIn', backref='borrowed_book')

worksAt = db.Table('works_at',
    db.Column('employee_id', db.Integer, db.ForeignKey('employees.id')),
    db.Column('branch_id', db.Integer, db.ForeignKey('branchs.id'))
)

class Branch(db.Model):
    __tablename__ = 'branchs'

    id = db.Column(db.Integer, primary_key=True)
    branchName = db.Column(db.String(50))
    street = db.Column(db.String(50))
    state = db.Column(db.String(50))
    city = db.Column(db.String(50))
    zip = db.Column(db.String(50))
    branch_manager_id = db.Column('branch_manager_id', db.Integer, db.ForeignKey('employees.id'))
    region_id = db.Column('region_id', db.Integer, db.ForeignKey('regions.id'))

    workers = db.relationship('Employees', secondary=worksAt, backref=db.backref('branch_worked', lazy='dynamic'))

class Region(db.Model):
    __tablename__ = 'regions'

    id = db.Column(db.Integer, primary_key=True)
    regionName = db.Column(db.String(50))
    regionManager = db.Column('regionManager', db.Integer, db.ForeignKey('employees.id'))
    
    branches = db.relationship('Branch', backref='region')

class CheckOut(db.Model):
    __tablename__ = 'check_outs'

    id = db.Column(db.Integer, primary_key=True)
    checkOutDate = db.Column(db.DateTime, default=date.today())
    dueDate = db.Column(db.DateTime, default = (date.today() + timedelta(days=30)))
    book_id = db.Column('book_id', db.Integer, db.ForeignKey('books.id'))
    member_id = db.Column('member_id', db.Integer, db.ForeignKey('members.id'))


class CheckIn(db.Model):
    __tablename__ = 'check_ins'

    id = db.Column(db.Integer, primary_key=True)
    checkInDate = db.Column(db.DateTime, default=date.today())
    book_id = db.Column('book_id', db.Integer, db.ForeignKey('books.id'))
    member_id = db.Column('member_id', db.Integer, db.ForeignKey('members.id'))

