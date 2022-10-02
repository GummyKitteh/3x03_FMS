from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, Email
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    logout_user,
    current_user,
)

app = Flask(__name__)
app.secret_key = "abcd"
app.config["SECRET_KEY"] = "I really hope fking this work if never idk what to do :("

# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:Barney-123@localhost/fmssql"
# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:qwerty1234@localhost/fmssql"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:B33pb33p!@178.128.17.35/fmssql"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(100))

    def __init__(self, name, email, phone):
        self.name = name
        self.email = email
        self.phone = phone


class datainsert(FlaskForm):
    name = StringField("Name", [DataRequired(), Length(max=50)])
    email = StringField("Email", [DataRequired(), Email(), Length(max=100)])
    phone = StringField("Phone", [DataRequired(), Length(min=8), Length(max=8)])
    submit = SubmitField("Submit", [DataRequired()])


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/employees")
def employees():
    all_data = Data.query.all()
    form = datainsert()
    return render_template("employees.html", employees=all_data)
    # return render_template("employees.html")


@app.context_processor
def employees():
    form = datainsert()
    return dict(form=form)


@app.route("/employees/insert", methods=["POST"])
def insert():
    form = datainsert()
    name = None
    email = None
    phone = None
    if request.method == "POST" and form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        phone = form.phone.data
        form.name.data = ""
        form.email.data = ""
        form.phone.data = ""
        my_data = Data(name, email, phone)
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


# class Employee(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True)
#     # username = db.Column(db.String())
#     username = db.Column(db.String(50), nullable=False)
#     email = db.Column(db.String(100), nullable=False)
#     contactNumber = db.Column(db.Integer, nullable=False)
#     password_hash = db.Column(db.String(64), nullable=False)


if __name__ == "__main__":
    app.run(debug=True)
