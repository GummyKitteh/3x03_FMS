from distutils.log import Log
from flask import Flask, render_template, request, redirect, url_for, flash

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import true, ForeignKey
from sqlalchemy.orm import declarative_base, relationship, backref

from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    SubmitField,
    SelectField,
    DateTimeField,
    DateField,
    DateTimeLocalField,
)
from wtforms.validators import DataRequired, Length, Email
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    login_required,
    logout_user,
    current_user,
)
from form import (
    RoleTypes,
    # tripInsert,
    employeeInsert,
    fleetInsert,
    TripStatusTypes,
    IntegerField,
    LoginForm,
)
from form import SearchFormEmployee, SearchFormFleet, SearchFormTrip

from enum import Enum

Base = declarative_base()

# from torch import equal
# import sys

app = Flask(__name__)
app.secret_key = "abcd"
app.config["SECRET_KEY"] = "I really hope fking this work if never idk what to do :("

# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:Barney-123@localhost/fmssql"
# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:qwerty1234@localhost/fmssql"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:B33pb33p!@178.128.17.35/fmssql"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# https://www.youtube.com/watch?v=4gRMV-wZTQs

# Emp_Dri = db.Table(
#     "emp_dri",
#     db.Column("employee_id", db.Integer, db.ForeignKey("employee.EmployeeId")),
#     db.Column("driver_id", db.Integer, db.ForeignKey("driver.EmployeeId")),
# )


class Employee(db.Model, UserMixin, Base):
    __tablename__ = "employee"
    EmployeeId = db.Column(db.Integer, primary_key=True)
    FullName = db.Column(db.String(50), nullable=False)
    Email = db.Column(db.String(100), nullable=False, unique=True)
    ContactNumber = db.Column(db.Integer, nullable=False)
    Role = db.Column(db.Enum(RoleTypes), nullable=False)
    Password = db.Column(db.String(64), nullable=False, unique=True)
    DOB = db.Column(db.DateTime, nullable=False)
    PasswordSalt = db.Column(db.String(64), nullable=False)

    driver_child = relationship("Driver", cascade="all, delete", backref="Employee")

    def __init__(
        self, FullName, Email, ContactNumber, Role, Password, DOB, PasswordSalt
    ):
        self.FullName = FullName
        self.Email = Email
        self.ContactNumber = ContactNumber
        self.Role = Role
        self.Password = Password
        self.DOB = DOB
        self.PasswordSalt = PasswordSalt

    def get_id(self):
        return self.EmployeeId


class Driver(db.Model, Base):
    __tablename__ = "driver"
    DriverId = db.Column(db.Integer, primary_key=True)
    EmployeeId = db.Column(
        db.Integer, db.ForeignKey("employee.EmployeeId", ondelete="CASCADE")
    )
    Assigned = db.Column(db.Integer, nullable=False)
    DriverStatus = db.Column(db.String(256), nullable=False)

    # dri_trip = db.relationship("Trip", backref="Driver", passive_deletes=True)

    def __init__(self, EmployeeId, Assigned, DriverStatus):
        self.EmployeeId = EmployeeId
        self.Assigned = Assigned
        self.DriverStatus = DriverStatus


class Fleet(db.Model):
    VehicleId = db.Column(db.Integer, primary_key=True)
    BusNumberPlate = db.Column(db.String(8), nullable=False)
    VehicleCapacity = db.Column(db.Integer, nullable=False)
    VehicleStatus = db.Column(db.String(45), nullable=False)

    def __init__(self, VehicleId, BusNumberPlate, VehicleCapacity, VehicleStatus):
        self.VehicleId = VehicleId
        self.BusNumberPlate = BusNumberPlate
        self.VehicleCapacity = VehicleCapacity
        self.VehicleStatus = VehicleStatus


class Trip(db.Model):
    TripID = db.Column(db.Integer, primary_key=True)
    DriverID = db.Column(db.Integer, nullable=False)
    VehicleID = db.Column(db.Integer, nullable=False)
    Origin = db.Column(db.String(256), nullable=False)
    Destination = db.Column(db.String(256), nullable=False)
    StartTime = db.Column(db.DateTime, nullable=False)
    EndTime = db.Column(db.DateTime, nullable=False)
    TripStatus = db.Column(db.Enum(TripStatusTypes), nullable=False)

    def __init__(
        self,
        DriverID,
        VehicleID,
        Origin,
        Destination,
        StartTime,
        EndTime,
        TripStatus,
    ):
        self.DriverID = DriverID
        self.VehicleID = VehicleID
        self.Origin = Origin
        self.Destination = Destination
        self.StartTime = StartTime
        self.EndTime = EndTime
        self.TripStatus = TripStatus


# Flask_login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(EmployeeId):
    try:
        return Employee.query.get(int(EmployeeId))
    except:
        return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    account = Employee.query
    if request.method == "POST" and form.validate_on_submit():
        user = account.filter_by(Email=form.Email.data).first()

        if user:
            if user.Password == form.password.data:
                login_user(user)
                # Check of role
                for role in RoleTypes:
                    if user.Role == role.manager:
                        # filter of query is
                        return redirect(url_for("employees"))
                    else:
                        return redirect(url_for("index"))
        else:
            return render_template("login.html", form=form)
    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/reset")
def reset():
    return render_template("reset.html")


# FLEET-------------------------------------------------------------------------------
@app.route("/fleet")
@login_required
def fleet():
    all_data = Fleet.query.all()
    return render_template("fleet.html", fleet=all_data)


@app.context_processor
def fleet():
    formFleet = fleetInsert()
    return dict(formFleet=formFleet)


@app.context_processor
def fleet():
    searchformFleet = SearchFormFleet()
    return dict(searchformFleet=searchformFleet)


@app.route("/fleet/fleetinsert", methods=["POST"])
def addFleet():
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


@app.route("/fleetUpdate", methods=["GET", "POST"])
def fleetUpdate():
    if request.method == "POST":
        fleet_data = Fleet.query.get(request.form.get("VehicleId"))
        fleet_data.BusNumberPlate = request.form["BusNumberPlate"]
        fleet_data.VehicleCapacity = request.form["VehicleCapacity"]
        fleet_data.VehicleStatus = request.form["VehicleStatus"]

        db.session.commit()
        flash("Vehicle Updated Successfully")

        return redirect(url_for("fleet"))


@app.route("/fleet/delete/<id>", methods=["GET", "POST"])
def delete(id):
    if request.method == "GET":
        fleet_data = Fleet.query.get(id)
        db.session.delete(fleet_data)
        db.session.commit()

        flash("Vehicle deleted sucessfully.")
        return redirect(url_for("fleet"))


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

    # FLEET END-------------------------------------------------------------------------------
    # EMPLOYEE -------------------------------------------------------------------------------


@app.route("/employees")
@login_required
def employees():
    all_data = Employee.query.all()
    # all_data = Employee.query.filter(Employee.Role == "admin")
    # all_data = Employee.query.filter(Employee.Role == "manager")
    # all_data = Employee.query.filter(Employee.Role == "driver")
    return render_template("employees.html", employees=all_data)


@app.context_processor
def employees():
    formEmployee = employeeInsert()
    return dict(formEmployee=formEmployee)


@app.context_processor
def employees():
    searchFormEmployee = SearchFormEmployee()
    return dict(searchFormEmployee=searchFormEmployee)


@app.route("/employees/insert", methods=["POST"])
def addEmployee():
    formEmployee = employeeInsert()
    FullName = None
    Email = None
    ContactNumber = None
    DOB = None
    Role = None
    Password = None
    if request.method == "POST" and formEmployee.validate_on_submit():
        FullName = formEmployee.FullName.data
        ContactNumber = formEmployee.ContactNumber.data
        Email = formEmployee.Email.data
        Role = formEmployee.Role.data
        Password = formEmployee.Password.data
        DOB = formEmployee.DOB.data
        PasswordSalt = formEmployee.Password.data
        formEmployee.FullName.data = ""
        formEmployee.ContactNumber.data = ""
        formEmployee.Email.data = ""
        formEmployee.DOB.data = ""
        formEmployee.Role.data = ""
        formEmployee.Password.data = ""
        formEmployee.Password.data = ""
        emp_data = Employee(
            FullName, Email, ContactNumber, Role, Password, DOB, PasswordSalt
        )
        db.session.add(emp_data)
        db.session.commit()

        if Role == "driver":
            obj = (
                db.session.query(Employee).order_by(Employee.EmployeeId.desc()).first()
            )
            driver_data = Driver(obj.EmployeeId, 1, "Account Created")
            emp_data.driver_child.append(driver_data)
            db.session.commit()

        flash("Employee inserted sucessfully")
        return redirect("/employees")
    else:
        flash("Employee insert failed")
        return redirect("/employees")


# @app.route("/update", methods=["GET", "POST"])
# def empployeeUpdate():
#     if request.method == "POST":
#         my_data = Employee.query.get(request.form.get("id"))
#         my_data.name = request.form["name"]
#         my_data.email = request.form["email"]
#         my_data.phone = request.form["phone"]

#         db.session.commit()
#         flash("Employee Updated Successfully")

#         return redirect(url_for("employees"))


@app.route("/employees/delete/<id>", methods=["GET", "POST"])
def employeeDelete(id):
    if request.method == "GET":
        my_data = Employee.query.get(id)
        db.session.delete(my_data)
        db.session.commit()

        flash("Employee deleted sucessfully.")
        return redirect(url_for("employees"))


@app.route("/employees/employeesearch", methods=["POST"])
def employeesearch():
    searchFormEmployee = SearchFormEmployee()
    posts = Employee.query
    if request.method == "POST" and searchFormEmployee.validate_on_submit():
        postsearched = searchFormEmployee.searched.data
        searchFormEmployee.searched.data = ""
        posts = posts.filter(Employee.FullName.like("%" + postsearched + "%"))
        posts = posts.order_by(Employee.EmployeeId).all()
        if posts != 0:
            return render_template(
                "Employees.html",
                SearchFormEmployee=searchFormEmployee,
                searched=postsearched,
                posts=posts,
            )
        else:
            flash("Cannot find Employee")


# EMPLOYEE END--------------------------------------------------------------------------
# TRIPS --------------------------------------------------------------------------------
@app.route("/trip")
@login_required
def trip():
    all_data = Trip.query.all()
    return render_template("trip.html", trip=all_data)


@app.context_processor
def trip():
    formTrip = tripInsert()
    return dict(formTrip=formTrip)


@app.context_processor
def trip():
    searchformTrip = SearchFormTrip()
    return dict(searchformTrip=searchformTrip)


class tripInsert(FlaskForm):
    EmployeeID = SelectField(
        "Driver",
        choices=[
            (row.EmployeeId, row.FullName)
            for row in Employee.query.filter_by(Role="driver")
        ],
    )
    VehicleID = SelectField(
        "Vehicle",
        choices=[(row.VehicleId, row.BusNumberPlate) for row in Fleet.query.all()],
    )
    Origin = StringField("Origin", [DataRequired(), Length(max=256)])
    Destination = StringField("Destination", [DataRequired(), Length(max=256)])
    StartTime = DateTimeLocalField("Start date & time", format="%Y-%m-%dT%H:%M")
    EndTime = DateTimeLocalField("End date & time", format="%Y-%m-%dT%H:%M")
    TripStatus = SelectField(
        "Status", choices=[(choice.name, choice.value) for choice in TripStatusTypes]
    )
    submit = SubmitField("Submit", [DataRequired()])


@app.route("/trip/tripinsert", methods=["POST"])
def addTrip():
    formTrip = tripInsert()

    if request.method == "POST" and formTrip.validate_on_submit():
        EmployeeID = formTrip.EmployeeID.data
        VehicleID = formTrip.VehicleID.data
        Origin = formTrip.Origin.data
        Destination = formTrip.Destination.data
        StartTime = formTrip.StartTime.data
        EndTime = formTrip.EndTime.data
        TripStatus = formTrip.TripStatus.data

        driverIDForInsert = (
            Driver.query.filter(Driver.EmployeeId == EmployeeID).first().DriverId
        )

        trip_data = Trip(
            driverIDForInsert,
            VehicleID,
            Origin,
            Destination,
            StartTime,
            EndTime,
            TripStatus,
        )
        db.session.add(trip_data)
        db.session.commit()
        flash("Trip inserted sucessfully")
        return redirect("/trip")
    else:
        flash("Trip insert failed.")
        return redirect("/trip")


@app.route("/trip/tripSearch", methods=["POST"])
def tripSearch():
    searchformTrip = SearchFormTrip()
    posts = Trip.query
    if request.method == "POST" and searchformTrip.validate_on_submit():
        postsearched = searchformTrip.searched.data
        searchformTrip.searched.data = ""
        posts = posts.filter(Trip.TripID.like("%" + postsearched + "%"))
        posts = posts.order_by(Trip.TripID).all()
        if posts != 0:
            return render_template(
                "trip.html",
                searchformTrip=searchformTrip,
                searched=postsearched,
                posts=posts,
            )
        else:
            flash("Cannot find Trip")


@app.route("/trip/tripUpdate", methods=["GET", "POST"])
def tripUpdate():
    if request.method == "POST":
        trip_data = Trip.query.get(request.form.get("TripID"))
        trip_data.DriverID = request.form["DriverID"]
        trip_data.VehicleID = request.form["VehicleID"]
        trip_data.Origin = request.form["Origin"]
        trip_data.Destination = request.form["Destination"]
        trip_data.StartTime = request.form["Start Time"]
        trip_data.EndTime = request.form["End Time"]
        trip_data.TripStatus = request.form["TripStatus"]

        db.session.commit()
        flash("Trip Updated Successfully")

        return redirect(url_for("trip"))


@app.route("/trip/delete/<id>", methods=["GET", "POST"])
def tripDelete(id):
    if request.method == "GET":
        trip_data = Trip.query.get(id)
        db.session.delete(trip_data)
        db.session.commit()

        flash("Trip deleted sucessfully.")
        return redirect(url_for("trip"))


# TRIPS END-----------------------------------------------------------------------------


if __name__ == "__main__":
    app.run(debug=True)
