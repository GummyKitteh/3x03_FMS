from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, DateTimeField, DateField
from wtforms.validators import DataRequired, Length, Email
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    logout_user,
    current_user,
)
from form import RoleTypes, employeeInsert, fleetInsert
from enum import Enum

# from torch import equal
from form import SearchFormEmployee, SearchFormFleet

import sys

app = Flask(__name__)
app.secret_key = "abcd"
app.config["SECRET_KEY"] = "I really hope fking this work if never idk what to do :("

# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:Barney-123@localhost/fmssql"
# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:qwerty1234@localhost/fmssql"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:B33pb33p!@178.128.17.35/fmssql"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# class Employee(db.Model):
#     EmployeeId = db.Column(db.Integer, primary_key=True)
#     FullName = db.Column(db.String(50), nullable=False)
#     Email = db.Column(db.String(100), nullable=False)
#     ContactNumber = db.Column(db.Integer, nullable=False)
#     Role = db.Column(db.Enum(RoleTypes), nullable=False)
#     Password = db.Column(db.String(64), nullable=False)
#     DOB = db.Column(db.DateTime, nullable=False)
#     PasswordSalt = db.Column(db.String(64), nullable=False)

#     def __init__(
#         self, FullName, Email, ContactNumber, Role, Password, DOB, PasswordSalt
#     ):
#         self.FullName = FullName
#         self.Email = Email
#         self.ContactNumber = ContactNumber
#         self.Role = Role
#         self.Password = Password
#         self.DOB = DOB
#         self.PasswordSalt = PasswordSalt


class Fleet(db.Model):
    VehicleId = db.Column(db.Integer, primary_key=True)
    BusNumberPlate = db.Column(db.String(8), nullable=False)
    VehicleCapacity = db.Column(db.Integer, nullable=False)
    VehicleStatus = db.Column(db.String(45), nullable=False)

    def __init__(self, BusNumberPlate, VehicleCapacity, VehicleStatus):
        self.BusNumberPlate = BusNumberPlate
        self.VehicleCapacity = VehicleCapacity
        self.VehicleStatus = VehicleStatus


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/reset")
def reset():
    return render_template("reset.html")


# FLEET-------------------------------------------------------------------------------
@app.route("/fleet")
def fleet():
    all_data = Fleet.query.all()
    return render_template("fleet.html", fleet=all_data)


@app.route("/fleet/fleetsearch", methods=["POST"])
def fleetsearch():
    searchform = SearchFormFleet()
    posts = Fleet.query
    if request.method == "POST" and searchform.validate_on_submit():
        postsearched = searchform.searched.data
        searchform.searched.data = ""
        posts = posts.filter(Fleet.BusNumberPlate.like("%" + postsearched + "%"))
        posts = posts.order_by(Fleet.VehicleId).all()
        if posts != 0:
            return render_template(
                "fleet.html",
                searchform=searchform,
                searched=postsearched,
                posts=posts,
            )
        else:
            flash("Cannot find Vehicle")


@app.context_processor
def fleet():
    formFleet = fleetInsert()
    return dict(formFleet=formFleet)


@app.route("/fleet/fleetinsert", methods=["POST"])
def fleetInsert():
    formFleet = fleetInsert()
    if request.method == "POST" and formFleet.validate_on_submit():
        BusNumberPlate = formFleet.BusNumberPlate.data
        VehicleCapacity = formFleet.VehicleCapacity.data
        VehicleStatus = formFleet.VehicleStatus.data
        fleet_data = Fleet(BusNumberPlate, VehicleCapacity, VehicleStatus)
        db.session.add(fleet_data)
        db.session.commit()
        flash("Vehicle inserted sucessfully")
        return redirect("/fleet")
    print("FAILURE")


@app.context_processor
def fleet():
    searchform = SearchFormFleet()
    return dict(searchform=searchform)


@app.route("/fleet/delete/<id>", methods=["GET", "POST"])
def delete(id):
    if request.method == "GET":
        fleet_data = Fleet.query.get(id)
        db.session.delete(fleet_data)
        db.session.commit()

        flash("Vehicle deleted sucessfully.")
        return redirect(url_for("fleet"))

    # FLEET END-------------------------------------------------------------------------------
    # EMPLOYEE -------------------------------------------------------------------------------

    # @app.route("/employees")
    # def employees():
    # return render_template("employees.html")
    # all_data = Employee.query.all()
    # return render_template("employees.html", employees=all_data)

    # @app.context_processor
    # def employees():
    #     form = employeeInsert()
    #     return dict(form=form)

    # @app.route("/employees/insert", methods=["POST"])
    # def insert():
    #     form = employeeInsert()
    #     FullName = None
    #     Email = None
    #     ContactNumber = None
    #     DOB = None
    #     Role = None
    #     Password = None
    #     if request.method == "POST" and form.validate_on_submit():
    #         FullName = form.FullName.data
    #         ContactNumber = form.ContactNumber.data
    #         Email = form.Email.data
    #         Role = form.Role.data
    #         Password = form.Password.data
    #         DOB = form.DOB.data
    #         PasswordSalt = form.Password.data
    #         form.FullName.data = ""
    #         form.ContactNumber.data = ""
    #         form.Email.data = ""
    #         form.DOB.data = ""
    #         form.Role.data = ""
    #         form.Password.data = ""
    #         form.Password.data = ""
    #         my_data = Employee(
    #             FullName, Email, ContactNumber, Role, Password, DOB, PasswordSalt
    #         )
    #         print(my_data)
    #         db.session.add(my_data)
    #         db.session.commit()
    #         flash("Employee Inserted Sucessfully")
    #         return redirect("/employees")
    #     print("FAILURE")

    # @app.route("/update", methods=["GET", "POST"])
    # def update():
    if request.method == "POST":
        my_data = Employee.query.get(request.form.get("id"))
        my_data.name = request.form["name"]
        my_data.email = request.form["email"]
        my_data.phone = request.form["phone"]

        db.session.commit()
        flash("Employee Updated Successfully")

        return redirect(url_for("employees"))

    # @app.route("/employees/delete/<id>", methods=["GET", "POST"])
    # def delete(id):
    # if request.method == "GET":
    #     my_data = Employee.query.get(id)
    #     db.session.delete(my_data)
    #     db.session.commit()

    #     flash("Employee deleted sucessfully.")
    #     return redirect(url_for("employees"))


# @app.context_processor
# def index():
#     searchform = SearchFormEmployee()
#     return dict(searchform=searchform)


# @app.route("/employees/employeesearch", methods=["POST"])
# def employeesearch():
#     searchform = SearchFormEmployee()
#     posts = Employee.query
#     if request.method == "POST" and searchform.validate_on_submit():
#         postsearched = searchform.searched.data
#         searchform.searched.data = ""
#         posts = posts.filter(Employee.FullName.like("%" + postsearched + "%"))
#         posts = posts.order_by(Employee.EmployeeId).all()
#         if posts != 0:
#             return render_template(
#                 "Employees.html",
#                 searchform=searchform,
#                 searched=postsearched,
#                 posts=posts,
#             )
#         else:
#             flash("Cannot find Employee")


if __name__ == "__main__":
    app.run(debug=True)
