from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
from threading import Thread

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
import logging, jwt
from time import strftime
from datetime import datetime

from form import LoginForm, ResetPasswordForm, NewPasswordForm
from form import employeeInsert, employeeUpdate, fleetInsert
from form import RoleTypes, TripStatusTypes
from form import SearchFormEmployee, SearchFormFleet, SearchFormTrip
from security_controls import *

Base = declarative_base()

app = Flask(__name__)
app.secret_key = "abcd"
app.config["SECRET_KEY"] = "I really hope fking this work if never idk what to do :("

# Db configuration
# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:Barney-123@localhost/fmssql"
# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:qwerty1234@localhost/fmssql"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:B33pb33p!@178.128.17.35/fmssql"
# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:qwert54321@localhost/fmssql"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Mail configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = "b33p33p@gmail.com"
#app.config["MAIL_PASSWORD"] = "<contact JM>"
app.config["MAIL_DEFAULT_SENDER"] = "b33p33p@gmail.com"
email_service = Mail(app)

#app.config["RECAPTCHA_PUBLIC_KEY"] = "<contact JM>"
#app.config["RECAPTCHA_PRIVATE_KEY"] = "<contact JM>"

# https://www.youtube.com/watch?v=4gRMV-wZTQs
# http://127.0.0.1:5000


# ----- LOGGGING ----------------------------------------------------------------------

logging.basicConfig(
    filename="./FMS/logs/generallog.log",
    encoding="utf-8",
    filemode="a",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

# Create Logger
# logger = logging.getLogger(__name__)
logger_auth = logging.getLogger("AUTH")
logger_crud = logging.getLogger("CRUD")

# Create FileHandler
handler_auth = logging.FileHandler(strftime(f"./FMS/logs/authlog_%d%m%y.log"))
handler_crud = logging.FileHandler(strftime(f"./FMS/logs/crudlog_%d%m%y.log"))

# Set Formatter for Logger
formatter_auth = logging.Formatter(
    "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
)
formatter_crud = logging.Formatter(
    "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
)

# Set Formatter to Handler
handler_auth.setFormatter(formatter_auth)
handler_crud.setFormatter(formatter_crud)

# Attach Handler to Logger
logger_auth.addHandler(handler_auth)
logger_crud.addHandler(handler_crud)

# logging.debug("This message should go to the log file")
# logging.info("So should this")
# logging.warning("And this, too")
# logging.error("And non-ASCII stuff, too, like Øresund and Malmö")

# ----- END LOGGGING ------------------------------------------------------------------
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
    AccountLocked = db.Column(db.Integer, nullable=False)
    LoginCounter = db.Column(db.Integer, nullable=False)
    LastLogin = db.Column(db.DateTime, nullable=False)
    #ResetToken = db.Column(db.String(64), nullable=False)
    #ResetDateTime = db.Column(db.DateTime, nullable=False)
    #OTP = db.Column(db.Integer, nullable=False)
    #OTPDateTime = db.Column(db.DateTime, nullable=False)

    driver_child = relationship("Driver", cascade="all, delete", backref="Employee")

    def __init__(
        self,
        FullName,
        Email,
        ContactNumber,
        Role,
        Password,
        DOB,
        PasswordSalt,
        AccountLocked,
        LoginCounter,
        LastLogin
        #ResetToken,
        #ResetDateTime,
        #OTP,
        #OTPDateTime
    ):
        self.FullName = FullName
        self.Email = Email
        self.ContactNumber = ContactNumber
        self.Role = Role
        self.Password = Password
        self.DOB = DOB
        self.PasswordSalt = PasswordSalt
        self.AccountLocked = AccountLocked
        self.LoginCounter = LoginCounter
        self.LastLogin = LastLogin
        #self.ResetToken = ResetToken
        #self.ResetDateTime = ResetDateTime
        #self.OTP = OTP
        #self.OTPDateTime = OTPDateTime

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

    trip_childFleet = relationship(
        "Trip",
        cascade="all, delete",
        backref="Fleet",
    )

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
    form = LoginForm(request.form)

    # If POST request
    if request.method == "POST":

        # If Form is validated
        if form.validate_on_submit():
            account = Employee.query
            user = account.filter_by(Email=form.Email.data).first()

            # If user exists in db
            if user:

                # Security Control
                derived_password = process_password(form.password.data, user.PasswordSalt)

                # If authenticated credentials
                if user.Password == derived_password:

                    # Reset LoginCounter
                    user.LoginCounter = 0
                    user.LastLogin = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    db.session.commit()

                    # Authorise login
                    login_user(user)
                    logger_auth.info(
                        f"{user.FullName} (ID: {user.EmployeeId}) has logged IN."
                    )
                    return redirect(url_for("employees"))

                # Else unauthenticated credentials
                else:
                    user.LoginCounter += 1
                    logger_auth.warning(
                        f"{user.FullName} (ID: {user.EmployeeId}) attempted to log in: {user.LoginCounter} time(s)."
                    )

                    # If accumulated 5 invalid attempts, lock user account
                    if user.LoginCounter == 5:
                        user.AccountLocked = 1
                        logger_auth.warning(
                            f"{user.FullName} (ID: {user.EmployeeId}) account has been locked after 5 incorrect login attempts."
                        )
                    db.session.commit()

                    # If user account is locked
                    if user.AccountLocked == 1:

                        # Send email to notify user
                        email = Message()
                        email.subject = "You Account Has Been Locked"
                        #email.recipients = [form.Email.data]
                        email.recipients = ["b33p33p@gmail.com"]
                        email.body = "Dear {},\n\nWe note that you have attempted to log in to your Bus FMS account multiple times without success.\nUnfortunately, your account has been locked after too many invalid login attempts.\n\nPlease contact your Manager or IT Administrator for assistance.\n\nThank you for your continued support in Bus FMS.\n\nBest regards,\nBus FMS".format(user.FullName)
                        #Thread(target=send_email, args=(app, email)).start()
                        print("Mimic: Email sent")

                        return render_template("login-locked.html")

        # Else Form is invalidated OR User does not exist in db
        message = ["You have entered an invalid Email and/or Password.", "Please try again."]
        return render_template("login.html", form=form, message=message)

    # Else GET request
    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    logger_auth.info("This fella has logged OUT.")
    return redirect(url_for("index"))


# ----- END LOGIN STUFF --------------------------------------------------------------
# ----- END RESET PASSWORD STUFF --------------------------------------------------------------


@app.route("/reset", methods=["GET", "POST"])
def reset():
    form = ResetPasswordForm(request.form)

    # If POST request
    if request.method == "POST":

        # If Form is validated
        if form.validate_on_submit():
            account = Employee.query
            user = account.filter_by(ContactNumber=form.Phone.data, Email=form.Email.data).first()

            # If user exists in db
            if user:

                # TODO: If user has sent a link in the last 1 hour


                # Craft email object
                email = Message()
                email.subject = "Password Reset Link"
                #email.recipients = [form.Email.data]
                email.recipients = ["b33p33p@gmail.com"]

                # If user account is locked (after 5 invalid attempts), send email without reset token
                if user.AccountLocked == 1:

                    # Send email object
                    email.body = "Dear {},\n\nYou have requested a password reset for your Bus FMS account.\n\nUnfortunately, your account has been locked after too many invalid attempts.\nPlease contact your Manager or IT Administrator for assistance.\n\nThank you for your continued support in Bus FMS.\n\nBest regards,\nBus FMS".format(user.FullName)
                    #Thread(target=send_email, args=(app, email)).start()
                    print("Mimic: Email sent")

                    # TODO: Commit email timestamp to db
                    #user.AccountLockedDateTime = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    #db.session.commit()

                # If user account is NOT locked, send email with reset token
                else:

                    # Generate reset token (output in Base64) for password reset
                    email_token = generate_reset_token(user.get_id())
                    #user.ResetDateTime = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    # user.ResetTokenFlag = 0
                    #db.session.commit()

                    # Send email object
                    reset_link = "http://localhost:5000/new-password/{}".format(email_token)
                    email.body = "Dear {},\n\nYou have requested a password reset for your Bus FMS account.\n\nKindly click on the link below, or copy it into your trusted Web Browser (i.e. Google Chrome), to do so.\nPlease note that the link is only valid for 1 hour.\nLink: {}\n\nYou may ignore this email if you did not make this request.\nRest assure that your account has not been compromised, and your information is safe with us!\n\nThank you for your continued support in Bus FMS.\n\nBest regards,\nBus FMS".format(user.FullName, reset_link)
                    #Thread(target=send_email, args=(app, email)).start()
                    print("Mimic: Email sent")

                    # Print for testing
                    print(reset_link)

            # Regardless if user exists or not, display generic message
            return render_template("reset/reset-message.html")

    # Else GET request OR Form is invalidated
    return render_template("reset/reset.html", form=form)


@app.route("/new-password/<email_token>", methods=["GET"])
def newPassword(email_token):
    form = NewPasswordForm(request.form)

    # Validate if email_token is still valid (within 1 hour AND not used yet)
    try:
        token_payload = decode_reset_token(email_token)
        # TODO: Validate if email_token has been used (user.ResetTokenFlag)

    except:
        return render_template("reset/reset-expired.html")

    # GET request
    return render_template("reset/new-password.html", form=form, email_token=email_token)


@app.route("/new-password", methods=["POST"])
def postPassword():
    form = NewPasswordForm(request.form)

    # Validate if email_token is still valid (within 1 hour AND not used yet)
    try:
        token_payload = decode_reset_token(form.EmailToken.data)
        # TODO: Validate if email_token has been used (user.ResetTokenFlag)

    except:
        return render_template("reset/reset-expired.html")

    # If POST request
    if request.method == "POST":

        # If Form is validated
        if form.validate_on_submit():
            account = Employee.query
            user = account.filter_by(EmployeeId=token_payload["reset_token"]).first()

            # If user exists in db
            if user:
                PasswordSalt = generate_csprng_token()  # 32-byte salt in hexadecimal
                
                # If password chosen is a common password
                is_common_password = check_common_password(form.NewPassword.data)
                if is_common_password:
                    message = ["Password chosen is a commonly used password.", "Please choose another."]
                    return render_template("reset/new-password.html", form=form, email_token=form.EmailToken.data, message=message)

                user.Password = process_password(form.NewPassword.data, PasswordSalt)
                user.PasswordSalt = PasswordSalt
                # user.ResetTokenFlag = 1
                db.session.commit()

                # TODO: Log user out of all logged-in sessions.

                return render_template("reset/reset-success.html")

    return render_template("reset/new-password.html", form=form, email_token=form.EmailToken.data)


@app.route("/reset-success", methods=["GET"])
def resetSuccess():
    
    # Only allow access if URL referrer is "new-password"
    try:
        if request.referrer.split("/")[-2] == "new-password":
            return render_template("reset/reset-success.html")
    except:
        return redirect(url_for("notFound"))


# ----- END RESET PASSWORD STUFF --------------------------------------------------------------
# ----- ROUTES -----------------------------------------------------------------------


@app.route("/")
def index():
    # app.logger.debug("debug")
    # app.logger.info("info")
    # app.logger.warning("warning")
    # app.logger.error("error")
    # app.logger.critical("critical")
    return render_template("index.html")


@app.route("/404")
def notFound():
    return render_template("404.html")


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
        obj = db.session.query(Fleet).order_by(Fleet.VehicleId.desc()).first()
        logger_crud.info(f"Vechicle (ID: {obj.VehicleId}) inserted to Fleet.")
        return redirect("/fleet")
    else:
        flash("Vehicle insert failed.")
        logger_crud.error(f"Vehicle insert failed.")
        return redirect("/fleet")


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

        return redirect(url_for("fleet", fleetupdate=fleetupdate))


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
    if request.method == "POST":
        FullName = formEmployee.FullName.data
        ContactNumber = formEmployee.ContactNumber.data
        Email = formEmployee.Email.data
        Role = formEmployee.Role.data
        DOB = formEmployee.DOB.data
        PasswordSalt = generate_csprng_token()  # 32-byte salt in hexadecimal
        is_common_password = check_common_password(formEmployee.Password.data)
        # If password chosen is a common password
        if is_common_password:
            flash(
                "Password chosen is a commonly used password. Please choose another.",
                "error",
            )
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

        if Role != "driver":
            flash("Employee inserted sucessfully")
            return redirect("/employees")
        else:
            obj = (
                db.session.query(Employee).order_by(Employee.EmployeeId.desc()).first()
            )
            driver_data = Driver(obj.EmployeeId, 1, "Account Created")
            emp_data.driver_child.append(driver_data)
            db.session.commit()

            flash("Driver inserted sucessfully")
            return redirect("/employees")
    else:
        flash("Employee insert failed")
        logger_crud.error(f"Employee insert failed.")
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
    # print(fleetList)
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

        return redirect(url_for("trip", tripupdate=tripupdate))


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
    updateFormEmployee = employeeUpdate()
    id = current_user.EmployeeId
    name_to_update = Employee.query.get_or_404(id)
    if request.method == "POST" and updateFormEmployee.validate_on_submit:
        name_to_update.FullName = request.form["FullName"]
        name_to_update.Email = request.form["Email"]
        name_to_update.ContactNumber = request.form["ContactNumber"]
        name_to_update.DOB = request.form["DOB"]

        derived_password = process_password(
            request.form["OldPassword"], name_to_update.PasswordSalt
        )
        if name_to_update.Password == derived_password:
            if request.form["ConfirmPassword"] == request.form["NewPassword"]:
                PasswordSalt = generate_csprng_token()  # 32-byte salt in hexadecimal
                is_common_password = check_common_password(request.form["NewPassword"])

                # If password chosen is a common password
                if is_common_password:
                    flash(
                        "Password chosen is a commonly used password. Please choose another.",
                        "error",
                    )

                else:
                    NewPassword = process_password(
                        request.form["NewPassword"], PasswordSalt
                    )
                    name_to_update.Password = NewPassword
                    name_to_update.PasswordSalt = PasswordSalt
                    db.session.commit()
                    flash("Profile has been updated")
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

def send_email(app, email):
    with app.app_context():
        email_service.send(email)


if __name__ == "__main__":
    app.run(debug=True)
