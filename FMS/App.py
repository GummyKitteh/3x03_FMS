from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, Email
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    logout_user,
    current_user,
)
from enum import Enum

app = Flask(__name__)
app.secret_key = "abcd"
app.config["SECRET_KEY"] = "I really hope fking this work if never idk what to do :("

# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:Barney-123@localhost/fmssql"
# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:qwerty1234@localhost/fmssql"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:B33pb33p!@178.128.17.35/fmssql"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# EMPLOYEE Classes
class RoleTypes(Enum):
    admin = "admin"
    manager = "manager"
    driver = "driver"


class Employee(db.Model):
    EmployeeId = db.Column(db.Integer, primary_key=True)
    FullName = db.Column(db.String(50), nullable=False)
    Email = db.Column(db.String(100), nullable=False)
    ContactNumber = db.Column(db.Integer, nullable=False)
    Role = db.Column(db.Enum(RoleTypes), nullable=False)
    Password = db.Column(db.String(64), nullable=False)
    DOB = db.Column(db.Date, nullable=False)
    PasswordSalt = db.Column(db.String(64), nullable=False)
    LoginCounter = db.Column(db.Integer, nullable=True)
    LastLogin = db.Column(db.Date, nullable=True)

    def __init__(
        self,
        FullName,
        Email,
        ContactNumber,
        Role,
        Password,
        DOB,
        PasswordSalt,
        LoginCounter,
        LastLogin,
    ):
        self.FullName = FullName
        self.Email = Email
        self.ContactNumber = ContactNumber
        self.Role = Role
        self.Password = Password
        self.DOB = DOB
        self.PasswordSalt = PasswordSalt
        self.LoginCounter = LoginCounter
        self.LastLogin = LastLogin


class employeeInsert(FlaskForm):
    FullName = StringField("Full Name", [DataRequired(), Length(max=50)])
    Email = StringField("Email", [DataRequired(), Email(), Length(max=100)])
    ContactNumber = StringField(
        "Contact Number", [DataRequired(), Length(min=8), Length(max=8)]
    )
    DOB = StringField("DOB", [DataRequired(), Length(max=20)])
    # Role = StringField("Role", [DataRequired(), Length(max=20)])
    Role = SelectField(
        "Role", choices=[(choice.name, choice.value) for choice in RoleTypes]
    )
    Password = StringField("Password", [DataRequired(), Length(min=8)])
    submit = SubmitField("Submit", [DataRequired()])


# class Data(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100))
#     email = db.Column(db.String(100))
#     phone = db.Column(db.String(100))

#     def __init__(self, name, email, phone):
#         self.name = name
#         self.email = email
#         self.phone = phone


# class datainsert(FlaskForm):
#     name = StringField("Name", [DataRequired(), Length(max=50)])
#     email = StringField("Email", [DataRequired(), Email(), Length(max=100)])
#     phone = StringField("Phone", [DataRequired(), Length(min=8), Length(max=8)])
#     submit = SubmitField("Submit", [DataRequired()])


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/employees")
def employees():
    all_data = Employee.query.all()
    return render_template("employees.html", employees=all_data)


@app.context_processor
def employees():
    form = employeeInsert()
    return dict(form=form)


@app.route("/employees/insert", methods=["POST"])
def insert():
    form = employeeInsert()
    FullName = None
    Email = None
    ContactNumber = None
    DOB = None
    Role = None
    Password = None
    PasswordSalt = "INSERT-PWD-SALT"
    LoginCounter = 0
    LastLogin = "INSERT-LASTLOGIN-SALT"
    if request.method == "POST" and form.validate_on_submit():
        FullName = form.FullName.data
        Email = form.Email.data
        ContactNumber = form.ContactNumber.data
        Role = form.Role.data
        DOB = form.DOB.data
        Password = form.Password.data
        my_data = Employee(
            FullName,
            Email,
            ContactNumber,
            DOB,
            Role,
            Password,
            PasswordSalt,
            LoginCounter,
            LastLogin,
        )
        db.session.add(my_data)
        db.session.commit()
        flash("Employee Inserted Sucessfully")
        return redirect("/employees")


@app.route("/employees/update", methods=["GET", "POST"])
def update():
    if request.method == "POST":
        my_data = Data.query.get(request.form.get("id"))
        my_data.name = request.form["name"]
        my_data.email = request.form["email"]
        my_data.phone = request.form["phone"]

        db.session.commit()
        flash("Employee Updated Successfully")

        return redirect(url_for("employees"))


@app.route("/employees/delete/<id>/", methods=["GET", "POST"])
def delete(id):
    if request.method == "GET":
        my_data = Data.query.get(id)
        db.session.delete(my_data)
        db.session.commit()

        flash("Employee Delete Sucessfully")
        return redirect(url_for("employees"))


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/reset")
def reset():
    return render_template("reset.html")


if __name__ == "__main__":
    app.run(debug=True)
