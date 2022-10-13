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

from form import employeeInsert, fleetInsert, LoginForm
from form import RoleTypes, TripStatusTypes
from form import SearchFormEmployee, SearchFormFleet, SearchFormTrip
from security_controls import *

Base = declarative_base()

app = Flask(__name__)
app.secret_key = "abcd"
app.config["SECRET_KEY"] = "I really hope fking this work if never idk what to do :("

# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:Barney-123@localhost/fmssql"
# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:qwerty1234@localhost/fmssql"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:B33pb33p!@178.128.17.35/fmssql_db"
# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:qwert54321@localhost/fmssql"
# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:B33pb33p!@178.128.17.35/fmssql"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# https://www.youtube.com/watch?v=4gRMV-wZTQs

# Emp_Dri = db.Table(
#     "emp_dri",
#     db.Column("employee_id", db.Integer, db.ForeignKey("employee.EmployeeId")),
#     db.Column("driver_id", db.Integer, db.ForeignKey("driver.EmployeeId")),
# )

# ----- CLASSES -----------------------------------------------------------------------


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

    trip_childDriver = relationship("Trip", cascade="all, delete", backref="Driver")

    def __init__(self, EmployeeId, Assigned, DriverStatus):
        self.EmployeeId = EmployeeId
        self.Assigned = Assigned
        self.DriverStatus = DriverStatus


class Fleet(db.Model):
    VehicleId = db.Column(db.Integer, primary_key=True)
    BusNumberPlate = db.Column(db.String(8), nullable=False)
    VehicleCapacity = db.Column(db.Integer, nullable=False)
    VehicleStatus = db.Column(db.String(45), nullable=False)

    trip_childFleet = relationship("Trip", cascade="all, delete", backref="Fleet")

    def __init__(self, BusNumberPlate, VehicleCapacity, VehicleStatus):
        self.BusNumberPlate = BusNumberPlate
        self.VehicleCapacity = VehicleCapacity
        self.VehicleStatus = VehicleStatus


class Trip(db.Model):
    TripID = db.Column(db.Integer, primary_key=True)
    DriverID = db.Column(
        db.Integer, db.ForeignKey("driver.DriverId", ondelete="CASCADE"), nullable=False
    )
    VehicleID = db.Column(
        db.Integer, db.ForeignKey("fleet.VehicleId", ondelete="CASCADE"), nullable=False
    )
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


# ----- END CLASSES -------------------------------------------------------------------
# ----- LOGIN STUFF -------------------------------------------------------------------


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


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    account = Employee.query
    if request.method == "POST" and form.validate_on_submit():
        user = account.filter_by(Email = form.Email.data).first()

        if user:
            derived_password = process_password(form.password.data, user.PasswordSalt)
            if user.Password == derived_password:
                login_user(user)

                return redirect(url_for("employees"))
        else:
            return render_template("login.html", form=form)
    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


# ----- END LOGIN STUFF --------------------------------------------------------------
# ----- ROUTES -----------------------------------------------------------------------


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/reset")
def reset():
    return render_template("reset.html")


# ----- END ROUTES -------------------------------------------------------------------
# ----- FLEET-------------------------------------------------------------------------


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

@app.context_processor
def fleet():
    fleetupdate = fleetInsert()
    return dict(fleetupdate=fleetupdate)
@app.route("/fleetUpdate", methods=["GET", "POST"])
def fleetUpdate():
    fleetupdate = fleetInsert()
    if request.method == "POST" and fleetupdate.validate_on_submit:
        fleet_data = Fleet.query.get(request.form.get("VehicleId"))
        fleet_data.BusNumberPlate = request.form["BusNumberPlate"]
        fleet_data.VehicleCapacity = request.form["VehicleCapacity"]
        fleet_data.VehicleStatus = request.form["VehicleStatus"]

        db.session.commit()
        flash("Vehicle Updated Successfully")

        return redirect(url_for("fleet",fleetupdate=fleetupdate))


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


# ----- FLEET END-------------------------------------------------------------------------
# ----- EMPLOYEE -------------------------------------------------------------------------


@app.route("/employees")
@login_required
def employees():
    userrole = current_user.Role
    if userrole == RoleTypes.admin:
        all_data = Employee.query.all()
        return render_template("employees.html", employees=all_data)

    elif userrole == RoleTypes.manager:
        all_data = Employee.query.filter(Employee.Role == "driver")
        return render_template("employees.html", employees=all_data)
    elif userrole == RoleTypes.driver:
        # all_data = Employee.query.filter(Employee.Email == current_user.Email)
        return render_template("trip.html")


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
        DOB = formEmployee.DOB.data

        PasswordSalt = generate_salt()  # 32-byte salt in hexadecimal
        is_common_password = secure_password(formEmployee.Password.data)
        
        # If password chosen is a common password
        if(is_common_password):
            flash("Password chosen is a commonly used password. Please choose another.", "error")
            return redirect("/employees")

        Password = process_password(formEmployee.Password.data, PasswordSalt)

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


# ----- EMPLOYEE END -------------------------------------------------------------------
# ----- TRIPS --------------------------------------------------------------------------


@app.route("/trip")
@login_required
def trip():
    trip_data = Trip.query.all()
    fleet_data = Fleet.query.all()
    # Fleet.
    return render_template("trip.html", trip=trip_data, fleet=fleet_data)


@app.context_processor
def trip():
    formTrip = tripInsert()
    return dict(formTrip=formTrip)


@app.context_processor
def trip():
    searchformTrip = SearchFormTrip()
    return dict(searchformTrip=searchformTrip)


def getFresh_Fleet():
    fleetList = []
    # get the Agencies from the database - syntax here would be SQLAlchemy
    fleet = Fleet.query.all()
    for a in fleet:
        # generate a new list of tuples
        fleetList.append((a.VehicleId, a.BusNumberPlate))
    print(fleetList)
    return fleetList


class tripInsert(FlaskForm):
    EmployeeID = SelectField(
        "Driver",
        choices=[
            (row.EmployeeId, row.FullName)
            for row in Employee.query.filter_by(Role="driver")
        ],
    )
    vehicleOptions = getFresh_Fleet()
    VehicleID = SelectField("Vehicle", choices=vehicleOptions)
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

@app.context_processor
def trip():
    tripupdate = tripInsert()
    return dict(tripupdate=tripupdate)
@app.route("/trip/tripUpdate", methods=["GET", "POST"])
def tripUpdate():
    tripupdate = tripInsert()
    if request.method == "POST" and tripupdate.validate_on_submit:
        trip_data = Trip.query.get(request.form.get("TripID"))
        trip_data.DriverID = request.form["DriverID"]
        trip_data.VehicleID = request.form["VehicleID"]
        trip_data.Origin = request.form["Origin"]
        trip_data.Destination = request.form["Destination"]
        trip_data.StartTime = request.form["StartTime"]
        trip_data.EndTime = request.form["EndTime"]
        trip_data.TripStatus = request.form["TripStatus"]

        db.session.commit()
        flash("Trip Updated Successfully")

        return redirect(url_for("trip",tripupdate=tripupdate))


@app.route("/trip/delete/<id>", methods=["GET", "POST"])
def tripDelete(id):
    if request.method == "GET":
        trip_data = Trip.query.get(id)
        db.session.delete(trip_data)
        db.session.commit()

        flash("Trip deleted sucessfully.")
        return redirect(url_for("trip"))


# ----- TRIPS END -----------------------------------------------------------------------
# ----- PROFILE INFO --------------------------------------------------------------------


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    updateFormEmployee = employeeInsert()
    id = current_user.EmployeeId
    name_to_update = Employee.query.get_or_404(id)
    if request.method == "POST" and updateFormEmployee.validate_on_submit:
        name_to_update.FullName = request.form["FullName"]
        name_to_update.Email = request.form["Email"]
        name_to_update.ContactNumber = request.form["ContactNumber"]
        name_to_update.DOB = request.form["DOB"]
        if name_to_update.Password == request.form["OldPassword"]:
            if request.form["ConfirmPassword"] == request.form["NewPassword"]:
                name_to_update.Password = request.form["NewPassword"]
                db.session.commit()
                flash("Profile Have Updated")
                return render_template(
                    "profile.html",
                    updateFormEmployee=updateFormEmployee,
                    name_to_update=name_to_update,
                )

            else:
                flash("Does not match new password or confirm password")
        else:
            flash("Password Incorrect")
    return render_template(
        "profile.html",
        updateFormEmployee=updateFormEmployee,
        name_to_update=name_to_update,
    )


# ----- END PROFILE INFO ---------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
