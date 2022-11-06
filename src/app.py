from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail
from threading import Thread

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import true, ForeignKey, or_
from sqlalchemy.orm import declarative_base, relationship, backref

from flask_session import Session

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
import logging, jwt, random
from time import strftime
from datetime import datetime, timedelta

from form import LoginForm, OTPForm, ResendOTPForm, ResetPasswordForm, NewPasswordForm
from form import employeeInsert, employeeUpdate, fleetInsert
from form import RoleTypes, TripStatusTypes
from form import SearchFormEmployee, SearchFormFleet, SearchFormTrip
from security_controls import GenerateCSPRNGToken, CheckCommonPassword, ProcessPassword, GenerateJWTToken, DecodeJWTToken
from email_controls import EmailNotificationUntimed, EmailNotificationTimed

import os
from dotenv import load_dotenv

load_dotenv()  # take environment variables from .env.
db_user = os.getenv("db_user")
db_pwd = os.getenv("db_pwd")
db_add = os.getenv("db_add")
db_db = os.getenv("db_db")
mail_user = os.getenv("mail_user")
mail_pwd = os.getenv("mail_pwd")
recaptcha_pub = os.getenv("recaptcha_pub")
recaptcha_prv = os.getenv("recaptcha_prv")

Base = declarative_base()

server = Flask(__name__)

# Session Config
server.config["SECRET_KEY"] = GenerateCSPRNGToken()
server.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)
server.config["SESSION_COOKIE_DOMAIN"] = None  # Might set to busfms.tk?
server.config["SESSION_COOKIE_HTTPONLY"] = True
server.config["SESSION_COOKIE_SECURE"] = True
server.config["SESSION_COOKIE_SAMESITE"] = "Strict"
# server.config["REMEMBER_COOKIE_HTTPONLY"] = True  # Duplicated?
# server.config["REMEMBER_COOKIE_SECURE"] = True    # Duplicated?
server.config["SESSION_TYPE"] = "sqlalchemy"
server.config["SESSION_USE_SIGNER"] = True
Session(server)

# Db configuration
server.config[
    "SQLALCHEMY_DATABASE_URI"
] = f"mysql+pymysql://{db_user}:{db_pwd}@{db_add}/{db_db}"
# server.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(server)
server.config["SESSION_SQLALCHEMY"] = db

# Mail configuration
server.config["MAIL_SERVER"] = "smtp.gmail.com"
server.config["MAIL_PORT"] = 587
server.config["MAIL_USE_TLS"] = True
server.config["MAIL_USE_SSL"] = False
server.config["MAIL_USERNAME"] = mail_user
server.config["MAIL_PASSWORD"] = mail_pwd
server.config["MAIL_DEFAULT_SENDER"] = mail_user
email_service = Mail(server)

server.config["RECAPTCHA_PUBLIC_KEY"] = recaptcha_pub
server.config["RECAPTCHA_PRIVATE_KEY"] = recaptcha_prv

# http://127.0.0.1:5000

# ----- LOGGGING ----------------------------------------------------------------------
full_path = os.path.realpath(__file__)
path, filename = os.path.split(full_path)
directory, folder = os.path.split(path)

# If as intended location
if (filename == "featureTest.py" and folder == "scripts") or (
    filename == "app.py" and folder == "src"
):
    location = path + "/logs"
elif filename == "featureTest.py" and folder != "scripts":
    location = path + "/scripts/logs"
elif filename == "app.py" and "flaskapp" in folder:
    location = path + "/logs"
elif filename == "app.py" and folder != "src":
    location = path + "/src/logs"
else:
    location = "ggwp"
    print("UNABLE TO FIND LOG FOLDER", full_path)

"""logging.basicConfig(
     filename=location + "/generallog.log",
     encoding="utf-8",
     filemode="a",
     level=logging.INFO,
     format="%(asctime)s | %(levelname)s | %(message)s",
)"""

# Create Logger
# logger = logging.getLogger(__name__)
logger_auth = logging.getLogger("AUTH")
logger_crud = logging.getLogger("CRUD")

# Create FileHandler
handler_auth = logging.FileHandler(strftime(location + f"/authlog_%d%m%y.log"))
handler_crud = logging.FileHandler(strftime(location + f"/crudlog_%d%m%y.log"))

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

# ----- END LOGGGING ------------------------------------------------------------------
# ----- CLASSES -----------------------------------------------------------------------


class Employee(db.Model, UserMixin, Base):
    __tablename__ = "employee"
    EmployeeId = db.Column(db.Integer, primary_key=True)
    FullName = db.Column(db.String(50), nullable=False)
    Email = db.Column(db.String(100), nullable=False, unique=True)
    ContactNumber = db.Column(db.Integer, nullable=False)
    Role = db.Column(db.Enum(RoleTypes), nullable=False)
    DOB = db.Column(db.DateTime, nullable=False)
    Password = db.Column(db.String(64), nullable=False)
    PasswordSalt = db.Column(db.String(64), nullable=False)
    AccountLocked = db.Column(db.Integer, nullable=False)
    AccountLockedDateTime = db.Column(db.Integer, nullable=False)
    LoginCounter = db.Column(db.Integer, nullable=False)
    LastLogin = db.Column(db.DateTime, nullable=False)
    ResetDateTime = db.Column(db.DateTime, nullable=False)
    ResetFlag = db.Column(db.Integer, nullable=False)
    OTP = db.Column(db.Integer, nullable=False)
    OTPDateTime = db.Column(db.DateTime, nullable=False)
    OTPCounter = db.Column(db.Integer, nullable=False)
    Disabled = db.Column(db.Integer, nullable=False)

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
        AccountLockedDateTime,
        LoginCounter,
        LastLogin,
        ResetDateTime,
        ResetFlag,
        OTP,
        OTPDateTime,
        OTPCounter,
        Disabled,
    ):
        self.FullName = FullName
        self.Email = Email
        self.ContactNumber = ContactNumber
        self.Role = Role
        self.Password = Password
        self.DOB = DOB
        self.PasswordSalt = PasswordSalt
        self.AccountLocked = AccountLocked
        self.AccountLockedDateTime = AccountLockedDateTime
        self.LoginCounter = LoginCounter
        self.LastLogin = LastLogin
        self.ResetDateTime = ResetDateTime
        self.ResetFlag = ResetFlag
        self.OTP = OTP
        self.OTPDateTime = OTPDateTime
        self.OTPCounter = OTPCounter
        self.Disabled = Disabled

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
    Disabled = db.Column(db.Integer, nullable=False)

    trip_childFleet = relationship(
        "Trip",
        cascade="all, delete",
        backref="Fleet",
    )

    def __init__(self, BusNumberPlate, VehicleCapacity, VehicleStatus, Disabled):
        self.BusNumberPlate = BusNumberPlate
        self.VehicleCapacity = VehicleCapacity
        self.VehicleStatus = VehicleStatus
        self.Disabled = Disabled


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
    Disabled = db.Column(db.Integer, nullable=False)

    def __init__(
        self,
        DriverID,
        VehicleID,
        Origin,
        Destination,
        StartTime,
        EndTime,
        TripStatus,
        Disabled,
    ):
        self.DriverID = DriverID
        self.VehicleID = VehicleID
        self.Origin = Origin
        self.Destination = Destination
        self.StartTime = StartTime
        self.EndTime = EndTime
        self.TripStatus = TripStatus
        self.Disabled = Disabled


class Sessions(db.Model):
    __tablename__ = "sessions"
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(255), nullable=False, unique=True)
    data = db.Column(db.LargeBinary)
    expiry = db.Column(db.DateTime, nullable=False)
    Employee_ID = db.Column(db.Integer, db.ForeignKey("employee.EmployeeId", ondelete="CASCADE")) # FK: "Employee_ID"

    def __init__(self, id, session_id, data, expiry, Employee_ID):
        self.id = id
        self.session_id = session_id
        self.data = data
        self.expiry = expiry
        self.Employee_ID = Employee_ID


# ----- END CLASSES -------------------------------------------------------------------
# ----- LOGIN STUFF -------------------------------------------------------------------


# Flask_login Stuff
login_manager = LoginManager()
login_manager.init_app(server)
login_manager.login_view = "login"
login_manager.session_protection = "strong"


@login_manager.user_loader
def load_user(EmployeeId):
    try:
        return Employee.query.get(int(EmployeeId))
    except:
        return None


@server.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = LoginForm(request.form)

    # If POST request
    if request.method == "POST":

        # If Form is validated
        if form.validate_on_submit():
            account = Employee.query
            sessioning = Sessions.query

            # Try if an invalid character was used in the Email input field
            try:
                user = account.filter_by(Email=form.Email.data).first()
            except:
                message = [
                    "You have entered an invalid Email and/or Password.",
                    "Please try again.",
                ]
                return render_template("login/login.html", form=form, message=message)

            # If user exists in db
            if user:

                # If user account is Locked or Disabled
                if user.AccountLocked or user.Disabled:

                    # Calculate time delta between current time and account locked time
                    try:
                        # If there is a timestamp in user.AccountLockedDateTime
                        email_token_delta = (
                            datetime.utcnow() - user.AccountLockedDateTime
                        ).total_seconds()
                        delta_minute = email_token_delta // 60
                    except:
                        # If there is no timestamp in user.AccountLockedDateTime
                        delta_minute = 10

                    # If user has NOT been notified of account lock or disable in the last 10 minutes
                    if delta_minute >= 10:

                        # Update AccountLockedDateTime to prevent user email spam
                        user.AccountLockedDateTime = datetime.utcnow().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                        db.session.commit()

                        # Send email to notify User
                        EmailNotificationUntimed(db, server, email_service, user, "login-locked-disabled")
                        print("Mimic: Email sent (Account Locked/Disabled)")

                        if user.Disabled:
                            logger_auth.warning(
                                f"{user.FullName} (ID: {user.EmployeeId}) (Account Disabled) attempted to log in."
                            )
                        else:
                            logger_auth.warning(
                                f"{user.FullName} (ID: {user.EmployeeId}) (Account Locked) attempted to log in."
                            )

                    message = [
                        "You have entered an invalid Email and/or Password.",
                        "Please try again.",
                    ]
                    return render_template("login/login.html", form=form, message=message)

                # Security Control
                derived_password = ProcessPassword(
                    form.password.data, user.PasswordSalt
                )
                # If authenticated credentials
                if user.Password == derived_password:

                    # If user has logged in before
                    if datetime.utcnow() > user.LastLogin:

                        """Temporarily Bypass OTP
                        # Reset LoginCounter
                        user.LoginCounter = 0
                        user.LastLogin = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                        user.OTP = 0
                        db.session.commit()
                        logger_auth.info(
                            f"{user.FullName} (ID: {user.EmployeeId}) has logged IN."
                        )
                        # Authorise login
                        login_user(user)  # , duration=timedelta(seconds=3))

                        # Session
                        user_session = sessioning.filter_by(session_id="session:"+session.sid).first()
                        user_session.Employee_ID = user.EmployeeId
                        # session["employee_id"] = user.EmployeeId
                        db.session.commit()

                        return redirect(url_for("employees"))

                        UNDO this for OTP."""
                        message = send_otp(user)
                        otp_form = OTPForm(request.form)
                        resend_form = ResendOTPForm(request.form)
                        return render_template(
                            "login/login-otp.html",
                            otp_form=otp_form,
                            resend_form=resend_form,
                            otp_token=GenerateJWTToken(user.get_id(), "otp"),
                            message=message,
                        )
                        #"""

                    # Else user has never logged in before (i.e. First login)
                    else:

                        # Send email w/ Reset Link to welcome User
                        EmailNotificationTimed(db, server, email_service, user, "login-welcome")
                        print("Mimic: Email sent")
                        logger_auth.warning(
                            f"{user.FullName} (ID: {user.EmployeeId}) logs in for the first time and has requested a password reset via Email."
                        )

                        return render_template("login/login-first-time-message.html")

                # Else unauthenticated credentials
                else:
                    user.LoginCounter += 1
                    logger_auth.warning(
                        f"{user.FullName} (ID: {user.EmployeeId}) attempted to log in: {user.LoginCounter} time(s)."
                    )
                    db.session.commit()

                    # If accumulated 5 invalid attempts, lock user account
                    if user.LoginCounter == 5:
                        user.AccountLocked = 1
                        user.AccountLockedDateTime = datetime.utcnow().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                        db.session.commit()

                        # Send email to notify User
                        EmailNotificationUntimed(db, server, email_service, user, "login-locked-disabled")
                        print("Mimic: Email sent (Account Locked/Disabled)")

                        # Send email to notify Administrator
                        EmailNotificationUntimed(db, server, email_service, user, "login-admin")
                        print("Mimic: Email sent to Admin (Account Locked)")
                        logger_auth.warning(
                            f"{user.Email} (ID: {user.EmployeeId}) account has been locked after 5 incorrect login attempts."
                        )

                        # Render Account Locked page ONLY ONCE to prevent account guessing
                        return render_template("login/account-locked.html")

        # Else Form is invalidated OR User does not exist in db
        message = [
            "You have entered an invalid Email and/or Password.",
            "Please try again.",
        ]
        return render_template("login/login.html", form=form, message=message)

    # Else GET request
    return render_template("login/login.html", form=form)


def send_otp(user):
    if user.OTPCounter == 0:
        message = [
            "An OTP has been sent to your email.",
            "Please submit the correct OTP.",
        ]
    else:
        message = [
            "A new OTP has been sent to your email.",
            "Please submit the latest OTP.",
        ]

    # Generate OTP
    random.seed(
        GenerateCSPRNGToken()
    )  # Set random.seed() with 32-byte hexadecimal salt
    user.OTP = random.randint(100000, 999999)
    user.OTPDateTime = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    user.OTPCounter = 0
    db.session.commit()

    # Send email to notify User the requested OTP
    EmailNotificationUntimed(db, server, email_service, user, "send-otp")
    print("Mimic: Email sent")
    logger_auth.warning(
        f"{user.FullName} (ID: {user.EmployeeId}) requested an OTP via Email."
    )

    # Print for testing
    print(user.OTP)

    return message


@server.route("/otp", methods=["GET", "POST"])
def validate_otp():
    otp_form = OTPForm(request.form)
    resend_form = ResendOTPForm(request.form)

    # If POST request
    if request.method == "POST":

        # If Form is validated
        if otp_form.validate_on_submit():
            account = Employee.query
            sessioning = Sessions.query

            # Validate if JWT token for OTPToken is still valid (within 5 minutes)
            try:
                token_payload = DecodeJWTToken(otp_form.OTPToken.data)
                print(token_payload)
                employeeID = token_payload["otp_userid"]
            except:
                form = LoginForm(request.form)
                message = ["Your OTP session has expired.", "Please try again."]
                return render_template("login/login.html", form=form, message=message)

            # If JWT Token is compromised,
            # continue to try if an invalid character was used in the hidden OTPToken input field
            try:
                int(employeeID)
                user = account.filter_by(EmployeeId=employeeID).first()
                if user == None:
                    raise
            except:
                form = LoginForm(request.form)
                message = [
                    "You do not have the rights to do that.",
                    "Please try again.",
                ]
                return render_template("login/login.html", form=form, message=message)

            # If user exists in db
            if user:

                # If OTP has been attempted 5 times, invalidate the OTP
                if user.OTPCounter == 5:
                    message = ["Your OTP has expired.", "Please request for a new OTP."]
                    return render_template(
                        "login/login-otp.html",
                        otp_form=otp_form,
                        resend_form=resend_form,
                        otp_token=otp_form.OTPToken.data,
                        message=message,
                    )

                # If user account is Locked or Disabled during OTP authentication, render relevant page
                if user.AccountLocked:
                    return render_template("login/account-locked.html")
                elif user.Disabled:
                    return render_template("login/account-disabled.html")

                # Calculate time delta between current time and time of OTP creation
                otp_delta = (datetime.utcnow() - user.OTPDateTime).total_seconds()
                if otp_delta <= 120:  # If OTP validity is within 120 seconds

                    # If OTP same, then login
                    if int(otp_form.OTP.data) == user.OTP:

                        # Reset LoginCounter
                        user.LoginCounter = 0
                        user.LastLogin = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                        user.OTP = 0

                        # Log out from / Destroy existing sessions
                        # Set Sessions
                        user_session = sessioning.filter_by(session_id="session:"+session.sid).first()
                        user_session.Employee_ID = user.EmployeeId
                        # session["employee_id"] = user.EmployeeId

                        # Commit to DB
                        db.session.commit()
                        logger_auth.info(
                            f"{user.FullName} (ID: {user.EmployeeId}) has logged IN."
                        )
                        # Authorise login
                        login_user(user)

                        return redirect(url_for("employees"))

                    # Else GET OTP page
                    else:
                        user.OTPCounter += 1
                        db.session.commit()
                        message = [
                            "You have entered an invalid OTP.",
                            "Please try again.",
                        ]

                        if user.OTPCounter == 5:
                            message = [
                                "Your OTP has expired.",
                                "Please request for a new OTP.",
                            ]

                        logger_auth.warning(
                            f"{user.FullName} (ID: {user.EmployeeId}) attempted to submit OTP: {user.OTPCounter} time(s)."
                        )
                        return render_template(
                            "login/login-otp.html",
                            otp_form=otp_form,
                            resend_form=resend_form,
                            otp_token=otp_form.OTPToken.data,
                            message=message,
                        )

                # Else OTP exceeds the 120 seconds valiity
                else:
                    message = ["Your OTP has expired.", "Please request for a new OTP."]
                    return render_template(
                        "login/login-otp.html",
                        otp_form=otp_form,
                        resend_form=resend_form,
                        otp_token=otp_form.OTPToken.data,
                        message=message,
                    )

        # Else Form is invalidated
        message = [
            "This form is not validated correctly.",
            "Please try again.",
        ]
        return render_template(
            "login/login-otp.html",
            otp_form=otp_form,
            resend_form=resend_form,
            otp_token=otp_form.OTPToken.data,
            message=message
        )

    # Else GET request
    else:
        return redirect(url_for("notFound"))


@server.route("/resend-otp", methods=["POST"])
def resend_otp():
    otp_form = OTPForm(request.form)
    resend_form = ResendOTPForm(request.form)

    # If Form is validated
    if resend_form.validate_on_submit():
        account = Employee.query

        # Validate if JWT token for OTPToken is still valid (within 5 minutes)
        try:
            token_payload = DecodeJWTToken(resend_form.OTPToken.data)
            employeeID = token_payload["otp_userid"]
        except:
            form = LoginForm(request.form)
            message = ["Your OTP session has expired.", "Please try again."]
            return render_template("login/login.html", form=form, message=message)

        # If JWT Token is compromised,
        # continue to try if an invalid character was used in the hidden OTPToken input field
        try:
            int(employeeID)
            user = account.filter_by(EmployeeId=employeeID).first()
            if user == None:
                raise
        except:
            form = LoginForm(request.form)
            message = [
                "You do not have the rights to do that.",
                "Please try again.",
            ]
            return render_template("login/login.html", form=form, message=message)

        # If user exists in db
        if user:

            # Resend OTP
            message = send_otp(user)
            resend_form = ResendOTPForm(request.form)
            return render_template(
                "login/login-otp.html",
                otp_form=otp_form,
                resend_form=resend_form,
                otp_token=resend_form.OTPToken.data,
                message=message,
            )

    # Else Form is invalidated
    message = [
        "This form is not validated correctly.",
        "Please try again.",
    ]
    return render_template(
        "login/login-otp.html",
        otp_form=otp_form,
        resend_form=resend_form,
        otp_token=resend_form.OTPToken.data,
        message=message,
    )


@server.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logger_auth.info(
        f"{current_user.FullName} (ID: {current_user.EmployeeId}) has logged OUT."
    )
    logout_user()
    session.clear()
    #session.pop("employee_id")
    return redirect(url_for("index"))


# ----- END LOGIN STUFF --------------------------------------------------------------
# ----- RESET PASSWORD STUFF --------------------------------------------------------------


@server.route("/reset", methods=["GET", "POST"])
def reset():
    form = ResetPasswordForm(request.form)

    # If POST request
    if request.method == "POST":

        # If Form is validated
        if form.validate_on_submit():
            account = Employee.query

            # Try if an invalid character was used in the input fields
            try:
                user = account.filter_by(
                    ContactNumber=form.Phone.data, Email=form.Email.data
                ).first()
            except:
                message = [
                    "At least 1 input field contains an invalid character.",
                    "Please try again.",
                ]
                return render_template("reset/reset.html", form=form, message=message)

            # If user exists in db
            if user:

                # Don't do anything if user account is disabled (by IT Admin)
                if user.Disabled:
                    logger_auth.warning(
                        f"{user.FullName} (ID: {user.EmployeeId}) (Account Disabled) attempted to request for a password reset."
                    )
                    pass

                # Send email w/o Reset Link if user account is locked (after 5 invalid attempts)
                elif user.AccountLocked:
                    EmailNotificationTimed(db, server, email_service, user, "reset-locked")
                    logger_auth.warning(
                        f"{user.FullName} (ID: {user.EmployeeId}) (Account Locked) requested a password reset via Email."
                    )

                # Send email w/ Reset Link if user account is NOT locked
                else:
                    EmailNotificationTimed(db, server, email_service, user, "reset-not-locked")
                    logger_auth.warning(
                        f"{user.FullName} (ID: {user.EmployeeId}) requested a password reset via Email."
                    )
                print("Mimic: Email sent")

            # Regardless if user exists or not, display generic message
            return render_template("reset/reset-message.html")

    # Else GET request OR Form is invalidated
    return render_template("reset/reset.html", form=form)


@server.route("/new-password/<email_token>", methods=["GET"])
def newPassword(email_token):
    form = NewPasswordForm(request.form)

    try:
        # Validate if email_token is still valid (within 1 hour)
        token_payload = DecodeJWTToken(email_token)

        # Validate if email_token has not been used yet
        account = Employee.query
        user = account.filter_by(EmployeeId=token_payload["reset_token"]).first()

        # If user exists in db
        if user:
            if not user.ResetFlag:  # 0 means Reset Link is NOT VALID & has been used
                return render_template("reset/reset-expired.html")
            if user.Disabled:  # 1 means user account is disabled (by IT Admin)
                return render_template("login/account-disabled.html")
            if user.AccountLocked:  # 1 means user account is locked (after 5 invalid attempts)
                return render_template("login/account-locked.html")
        else:
            return render_template("reset/reset-expired.html")

    except:
        return render_template("reset/reset-expired.html")

    # GET request if email_token is still valid & not been used
    return render_template(
        "reset/new-password.html", form=form, email_token=email_token
    )


@server.route("/new-password", methods=["POST"])
def postPassword():
    form = NewPasswordForm(request.form)

    try:
        # Validate if email_token is still valid (within 1 hour)
        token_payload = DecodeJWTToken(form.EmailToken.data)

        # Validate if email_token has not been used yet
        account = Employee.query
        user = account.filter_by(EmployeeId=token_payload["reset_token"]).first()

        # If user exists in db
        if user:
            if not user.ResetFlag:  # 0 means Reset Link is NOT VALID & has been used
                return render_template("reset/reset-expired.html")
            if user.Disabled:  # 1 means user account is disabled (by IT Admin)
                return render_template("login/account-disabled.html")
            if user.AccountLocked:  # 1 means user account is locked (after 5 invalid attempts)
                return render_template("login/account-locked.html")
        else:
            return render_template("reset/reset-expired.html")

    except:
        return render_template("reset/reset-expired.html")

    # If POST request
    if request.method == "POST":

        # If Form is validated
        if form.validate_on_submit():

            PasswordSalt = GenerateCSPRNGToken()  # 32-byte salt in hexadecimal

            # If password chosen is a common password
            is_common_password = CheckCommonPassword(form.NewPassword.data)
            if is_common_password:
                message = [
                    "Password chosen is a commonly used password.",
                    "Please choose another.",
                ]
                return render_template(
                    "reset/new-password.html",
                    form=form,
                    email_token=form.EmailToken.data,
                    message=message,
                )

            # Try if an invalid character was used in the Password input field
            try:
                user.Password = ProcessPassword(form.NewPassword.data, PasswordSalt)
                user.PasswordSalt = PasswordSalt
                user.ResetFlag = 0  # 0 means Reset Link is NOT VALID & has been used
                user.LoginCounter = 0

                # If this is the first time resetting a password
                if user.LastLogin > datetime.utcnow():
                    user.LastLogin = "1970-01-01 00:00:01"

                db.session.commit()
            except:
                message = [
                    "Password chosen contains invalid characters.",
                    "Please choose another.",
                ]
                return render_template(
                    "reset/new-password.html",
                    form=form,
                    email_token=form.EmailToken.data,
                    message=message,
                )

            # Send Email to notify User that Password has been changed
            EmailNotificationUntimed(db, server, email_service, user, "new-password")
            print("Mimic: Email sent")

            # Log user out of all logged-in sessions.
            logout_user()
            session.clear()
            #session.pop("employee_id")

            logger_auth.info(
                f"{user.FullName} (ID: {user.EmployeeId}) has performed a password reset. Notification email has been sent to the User."
            )

            return render_template("reset/reset-success.html")

        # Else Form is invalidated
        message = [
            "This form is not validated correctly.",
            "Please try again.",
        ]
        return render_template("reset/new-password.html", form=form, email_token=form.EmailToken.data, message=message)

    return render_template(
        "reset/new-password.html", form=form, email_token=form.EmailToken.data
    )


@server.route("/reset-success", methods=["GET"])
def resetSuccess():

    # Only allow access if URL referrer is "new-password"
    try:
        if request.referrer.split("/")[-2] == "new-password":
            return render_template("reset/reset-success.html")
    except:
        return redirect(url_for("notFound"))


# ----- END RESET PASSWORD STUFF --------------------------------------------------------------
# ----- ROUTES -----------------------------------------------------------------------


@server.route("/")
def index():
    return render_template("index.html")


@server.errorhandler(404)
@server.errorhandler(405)
@server.errorhandler(500)
def notFound(error):
    return render_template("404.html"), 404


@server.route("/404")
def notFound():
    return render_template("404.html")


@server.route("/notauthorized")
def notAuthorized():
    return render_template("notauthorized.html")


# ----- END ROUTES -------------------------------------------------------------------
# ----- FLEET-------------------------------------------------------------------------


@server.route("/fleet")
@login_required
def fleet():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "driver" or current_user.Role.value == "admin":
        return redirect("/notauthorized")
    else:
        all_data = Fleet.query.all()
        return render_template("fleet.html", fleet=all_data)


@server.route("/fleetview")
@login_required
def fleetview():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "driver":
        all_data = Fleet.query.all()
        return render_template("fleetview.html", fleet=all_data)
    else:
        return redirect("/notauthorized")


@server.context_processor
def fleet():
    formFleet = fleetInsert()
    return dict(formFleet=formFleet)


@server.context_processor
def fleet():
    searchformFleet = SearchFormFleet()
    return dict(searchformFleet=searchformFleet)


@server.route("/fleet/fleetinsert", methods=["POST"])
def addFleet():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "manager":
        formFleet = fleetInsert()
        if request.method == "POST" and formFleet.validate_on_submit():
            BusNumberPlate = formFleet.BusNumberPlate.data
            VehicleCapacity = formFleet.VehicleCapacity.data
            VehicleStatus = formFleet.VehicleStatus.data
            Disabled = 0
            fleet_data = Fleet(BusNumberPlate, VehicleCapacity, VehicleStatus, Disabled)

            # If an invalid character was used in any input field
            try:
                db.session.add(fleet_data)
                db.session.commit()
            except:
                flash(
                    "At least 1 input field contains an invalid character. Please try again."
                )
                return redirect("/fleet")

            obj = db.session.query(Fleet).order_by(Fleet.VehicleId.desc()).first()
            logger_crud.info(
                f"Vechicle (ID: {obj.VehicleId}) inserted to Fleet by EmployeeID: {current_user.EmployeeId}."
            )
            flash("Vehicle inserted sucessfully.")
            return redirect("/fleet")

        else:
            logger_crud.error(
                f"Vehicle insert failed by EmployeeID: {current_user.EmployeeId}."
            )
            flash("Vehicle insert failed.")
            return redirect("/fleet")

    else:
        return redirect("/notauthorized")


@server.context_processor
def fleet():
    fleetupdate = fleetInsert()
    return dict(fleetupdate=fleetupdate)


@server.route("/fleetUpdate", methods=["GET", "POST"])
def fleetUpdate():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "manager":
        fleetupdate = fleetInsert()
        if request.method == "POST" and fleetupdate.validate_on_submit:
            vID = request.form.get("VehicleId")
            fleet_data = Fleet.query.get(request.form.get("VehicleId"))
            fleet_data.BusNumberPlate = request.form["BusNumberPlate"]
            fleet_data.VehicleCapacity = request.form["VehicleCapacity"]
            fleet_data.VehicleStatus = request.form["VehicleStatus"]

            # If an invalid character was used in any input field
            try:
                db.session.commit()
            except:
                flash(
                    "At least 1 input field contains an invalid character. Please try again."
                )
                return redirect(url_for("fleet", fleetupdate=fleetupdate))

            logger_crud.info(
                f"Vechicle (ID: {vID}) was updated in Fleet by EmployeeID: {current_user.EmployeeId}."
            )
            flash("Vehicle Updated Successfully")
            return redirect(url_for("fleet", fleetupdate=fleetupdate))
    else:
        vID = request.form.get("VehicleId")
        logger_crud.error(
            f"Vechicle (ID: {vID}) update failed by EmployeeID: {current_user.EmployeeId}."
        )
        return redirect("/notauthorized")


@server.route("/fleet/delete/<id>", methods=["GET", "POST"])
def delete(id):
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "manager":
        if request.method == "GET":
            fleet_data = Fleet.query.get(id)
            # if fleet_data.Disabled == 1:
            #     fleet_data.Disabled = 0
            #     logger_crud.info(f"Vechicle (ID: {id}) ENABLED in Fleet.")
            #     flash("Vehicle enabled sucessfully.")
            # else:
            #     fleet_data.Disabled = 1
            #     logger_crud.info(f"Vechicle (ID: {id}) DISABLED in Fleet.")
            #     flash("Vehicle disabled sucessfully.")
            # db.session.commit()

            # If fleet is unable to be deleted from the database
            try:
                db.session.delete(fleet_data)
                db.session.commit()
            except:
                flash("Fleet is unable to be deleted. Please try again.")
                logger_crud.error(
                    f"Vechicle (ID: {id}) delete failed by EmployeeID: {current_user.EmployeeId}."
                )
                return redirect(url_for("fleet"))

            logger_crud.info(
                f"Vechicle (ID: {id}) deleted from fleet by EmployeeID: {current_user.EmployeeId}."
            )
            flash("Vehicle deleted sucessfully.")
            return redirect(url_for("fleet"))

    else:
        return redirect("/notauthorized")


@server.route("/fleet/fleetsearch", methods=["POST"])
def fleetsearch():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "manager":
        searchform = SearchFormFleet()
        posts = Fleet.query
        if request.method == "POST" and searchform.validate_on_submit():
            postsearched = searchform.searched.data
            searchform.searched.data = ""
            logger_crud.info(
                f"[{postsearched}] searched in fleet by Employee (ID: {current_user.EmployeeId})."
            )
            # If an invalid character was used in any search query field
            try:
                posts = posts.filter(
                    Fleet.BusNumberPlate.like("%" + postsearched + "%")
                )
                posts = posts.order_by(Fleet.VehicleId).all()
            except:
                posts = 0
                flash(
                    "At least 1 input field contains an invalid character. Please try again."
                )
                logger_crud.warning(
                    f"Empty search done by by EmployeeID: {current_user.EmployeeId}."
                )
                return render_template(
                    "fleet.html",
                    searchform=searchform,
                    searched=postsearched,
                    posts=posts,
                )

            # posts returns empty list if no results found
            if len(posts) == 0:
                posts = 0
                logger_crud.warning(
                    f"No results found in fleet search by Employee (ID: {current_user.EmployeeId})."
                )

            if posts != 0:
                return render_template(
                    "fleet.html",
                    searchform=searchform,
                    searched=postsearched,
                    posts=posts,
                )
            else:
                flash("Cannot find Vehicle")
                return render_template(
                    "fleet.html",
                    searchform=searchform,
                    searched=postsearched,
                    posts=posts,
                )
    else:
        return redirect("/notauthorized")


# ----- FLEET END-------------------------------------------------------------------------
# ----- EMPLOYEE -------------------------------------------------------------------------


@server.route("/employees")
@login_required
def employees():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    userrole = current_user.Role
    if userrole == RoleTypes.admin:
        manager_data = Employee.query.all()
        accLocked_data = Employee.query.filter(
            or_(Employee.AccountLocked == 1, Employee.Disabled == 1)
        )
        return render_template(
            "employees.html", employees=manager_data, lockedAcc=accLocked_data
        )
    elif userrole == RoleTypes.manager:
        all_data = Employee.query.filter(Employee.Role == "driver")
        return render_template("employees.html", employees=all_data)
    elif userrole == RoleTypes.driver:
        # all_data = Employee.query.filter(Employee.Email == current_user.Email)
        return redirect("/tripview")


@server.context_processor
def employees():
    accLocked_data = Employee.query.filter(Employee.AccountLocked == 1)
    return dict(lockedAcc=accLocked_data)


@server.context_processor
def employees():
    formEmployee = employeeInsert()
    return dict(formEmployee=formEmployee)


@server.context_processor
def employees():
    searchFormEmployee = SearchFormEmployee()
    return dict(searchFormEmployee=searchFormEmployee)


@server.route("/employees/insert", methods=["POST"])
def addEmployee():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")

    if current_user.Role.value == "manager" or current_user.Role.value == "admin":
        formEmployee = employeeInsert()
        FullName = None
        Email = None
        ContactNumber = None
        DOB = None
        Role = None
        Password = None
        AccountLock = 0
        AccountLockedDateTime = None
        LoginCounter = 0
        LastLogin = "2999-12-31 23:59:59"
        ResetDateTime = None
        ResetFlag = 0
        OTP = 0
        OTPDateTime = None
        OTPCounter = 0
        Disabled = 0
        if request.method == "POST" and formEmployee.validate_on_submit():
            account = Employee.query

            # Try if an invalid character was used in the Email input field
            try:
                user = account.filter_by(Email=formEmployee.Email.data).first()
            except:
                logger_crud.warning(
                    f"Employee insert failed by EmployeeID: {current_user.EmployeeId}."
                )
                flash(
                    "At least 1 input field contains an invalid character. Please try again."
                )
                return redirect("/employees")

            # If email does not exist in db
            if not user:
                FullName = formEmployee.FullName.data
                ContactNumber = formEmployee.ContactNumber.data
                Email = formEmployee.Email.data
                if current_user.Role.value == "manager":
                    Role = "driver"
                elif current_user.Role.value == "admin":
                    Role = "manager"

                DOB = formEmployee.DOB.data
                PasswordSalt = GenerateCSPRNGToken()  # 32-byte salt in hexadecimal
                is_common_password = CheckCommonPassword(formEmployee.Password.data)
                # If password chosen is a common password
                if is_common_password:
                    flash(
                        "Password chosen is a commonly used password. Please choose another.",
                        "error",
                    )
                    return redirect("/employees")

                # Need to check for Emoji
                # DB WONT HAVE ERROR
                Password = ProcessPassword(formEmployee.Password.data, PasswordSalt)

                formEmployee.FullName.data = ""
                formEmployee.ContactNumber.data = ""
                formEmployee.Email.data = ""
                formEmployee.DOB.data = ""
                formEmployee.Password.data = ""
                emp_data = Employee(
                    FullName,
                    Email,
                    ContactNumber,
                    Role,
                    Password,
                    DOB,
                    PasswordSalt,
                    AccountLock,
                    AccountLockedDateTime,
                    LoginCounter,
                    LastLogin,
                    ResetDateTime,
                    ResetFlag,
                    OTP,
                    OTPDateTime,
                    OTPCounter,
                    Disabled,
                )

                # If an invalid character was used in any input field
                try:
                    db.session.add(emp_data)
                    db.session.commit()
                except:
                    logger_crud.warning(
                        f"Employee insert failed by EmployeeID: {current_user.EmployeeId}."
                    )
                    flash(
                        "At least 1 input field contains an invalid character. Please try again."
                    )
                    return redirect("/employees")

                obj = (
                    db.session.query(Employee)
                    .order_by(Employee.EmployeeId.desc())
                    .first()
                )
                logger_crud.info(
                    f"Employee (ID: {obj.EmployeeId}) inserted to Employee by EmployeeID: {current_user.EmployeeId}."
                )

                if Role != "driver":
                    flash("Employee inserted sucessfully")
                    return redirect("/employees")
                else:
                    obj = (
                        db.session.query(Employee)
                        .order_by(Employee.EmployeeId.desc())
                        .first()
                    )
                    driver_data = Driver(obj.EmployeeId, 1, "Account Created")
                    emp_data.driver_child.append(driver_data)

                    # If driver is unable to be inserted
                    try:
                        db.session.commit()
                    except:
                        flash("Employee is unable to be inserted. Please try again.")
                        return redirect("/employees")

                    obj = (
                        db.session.query(Driver)
                        .order_by(Driver.DriverId.desc())
                        .first()
                    )
                    logger_crud.info(
                        f"Driver (ID: {obj.DriverId}) inserted to Driver by EmployeeID: {current_user.EmployeeId}."
                    )
                    # db.session.expire_all()

                    flash("Driver inserted sucessfully")
                    return redirect("/employees")

            # If email does exist in db
            else:
                flash("Email already exists. Please choose another.")
                return redirect("/employees")

        else:
            logger_crud.error(
                f"Employee insert failed by EmployeeID: {current_user.EmployeeId}."
            )
            flash("Employee insert failed. Please check your fields again.")
            return redirect("/employees")
    else:
        return redirect("/notauthorized")


@server.route("/employees/delete/<id>", methods=["GET", "POST"])
def employeeDelete(id):
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "admin" or current_user.Role.value == "manager":
        if request.method == "GET":
            my_data = Employee.query.get(id)

            # Enable employee account if Disabled
            if my_data.Disabled == 1:
                my_data.Disabled = 0
                my_data.AccountLocked = 0
                my_data.LoginCounter = 0
                my_data.OTPCounter = 0
                my_data.OTP = 0

                # Send Email to notify User that Account has been enabled
                EmailNotificationTimed(my_data, "Re-Enabled")
                print("Mimic: Email sent")
                logger_crud.info(
                    f"Employee (ID: {id}) ENABLED in Employee by EmployeeID: {current_user.EmployeeId}."
                )

                flash("Employee enabled sucessfully.")

            # Disable employee account if Enabled
            else:
                my_data.Disabled = 1
                my_data.AccountLocked = 1
                logger_crud.info(
                    f"Trip (ID: {id}) Disabled in Employee by EmployeeID: {current_user.EmployeeId}."
                )
                flash("Employee disabled sucessfully.")

            # If employee is unable to be disabled
            try:
                db.session.commit()
            except:
                flash("Employee is unable to be disabled. Please try again.")

            return redirect(url_for("employees"))
    else:
        return redirect("/notauthorized")


@server.route("/employees/unlock/<id>", methods=["GET", "POST"])
def employeeUnlock(id):
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "admin":
        if request.method == "GET":
            my_data = Employee.query.get(id)
            my_data.AccountLocked = 0
            my_data.LoginCounter = 0
            my_data.OTPCounter = 0
            my_data.OTP = 0

            # Send Email to notify User that Account has been unlocked
            EmailNotificationTimed(my_data, "Unlocked")
            print("Mimic: Email sent")
            logger_crud.info(
                f"Employee (ID: {id}) UNLOCKED in Employee by EmployeeID: {current_user.EmployeeId}."
            )

            flash("Employee UNLOCKED sucessfully.")

            # If employee is unable to be unlocked
            try:
                db.session.commit()
            except:
                flash("Employee is unable to be enabled. Please try again.")

            return redirect(url_for("employees"))

    else:
        return redirect("/notauthorized")


@server.route("/employees/employeesearch", methods=["POST"])
def employeesearch():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "manager" or current_user.Role.value == "admin":
        searchFormEmployee = SearchFormEmployee()
        posts = Employee.query
        if request.method == "POST" and searchFormEmployee.validate_on_submit():
            postsearched = searchFormEmployee.searched.data
            searchFormEmployee.searched.data = ""
            logger_crud.info(
                f"[{postsearched}] searched in employee by Employee (ID: {current_user.EmployeeId})."
            )
            # Try if an invalid character was used in the Email input field
            try:
                if current_user.Role.value == "admin":
                    posts = posts.filter(
                        Employee.FullName.like("%" + postsearched + "%"),
                        Employee.Role == "manager",
                    )
                    posts = posts.order_by(Employee.EmployeeId).all()
                    logger_crud.info(
                        f"[{postsearched}] searched in employee by Employee (ID: {current_user.EmployeeId})."
                    )
                elif current_user.Role.value == "manager":
                    posts = posts.filter(
                        Employee.FullName.like("%" + postsearched + "%"),
                        Employee.Role == "driver",
                    )
                    posts = posts.order_by(Employee.EmployeeId).all()
                else:
                    posts = 0
            except:
                posts = 0
                flash(
                    "At least 1 input field contains an invalid character. Please try again."
                )
                return render_template(
                    "employees.html",
                    SearchFormEmployee=searchFormEmployee,
                    searched=postsearched,
                    posts=posts,
                )

            # posts returns empty list if no results found
            if len(posts) == 0:
                posts = 0
                logger_crud.warning(
                    f"No results found in employee search by Employee (ID: {current_user.EmployeeId})."
                )

            if posts != 0:
                return render_template(
                    "employees.html",
                    SearchFormEmployee=searchFormEmployee,
                    searched=postsearched,
                    posts=posts,
                )
            else:
                flash("Cannot find Employee")
                return render_template(
                    "employees.html",
                    SearchFormEmployee=searchFormEmployee,
                    searched=postsearched,
                    posts=posts,
                )
    else:
        return redirect("/notauthorized")


# ----- EMPLOYEE END -------------------------------------------------------------------
# ----- TRIPS --------------------------------------------------------------------------


@server.route("/trip")
@login_required
def trip():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "manager":
        formTrip = tripInsert()
        employeeList = getFresh_Employee()
        fleetList = getFresh_Fleet()
        formTrip.EmployeeID.choices = employeeList
        formTrip.VehicleID.choices = fleetList
        trip_data = Trip.query.all()
        fleet_data = Fleet.query.all()
        return render_template(
            "trip.html", trip=trip_data, fleet=fleet_data, formTrip=formTrip
        )
    else:
        return redirect("/notauthorized")


@server.route("/tripview")
@login_required
def tripview():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "driver":
        driver_data = (
            Driver.query.filter(Driver.EmployeeId == current_user.EmployeeId)
            .first()
            .DriverId
        )
        trip_data = Trip.query.filter(Trip.DriverID == driver_data)
        return render_template("trip.html", trip=trip_data)
    else:
        return redirect("/notauthorized")


@server.context_processor
def trip():
    formTrip = tripInsert()
    return dict(formTrip=formTrip)


@server.context_processor
def trip():
    searchformTrip = SearchFormTrip()
    return dict(searchformTrip=searchformTrip)


def getFresh_Employee():
    employeeList = []
    employee = Employee.query.filter(Employee.Role == "driver", Employee.Disabled == 0)
    for row in employee:
        employeeList.append((row.EmployeeId, row.FullName))
    return employeeList


def getFresh_Fleet():
    fleetList = []
    fleet = Fleet.query.filter(Fleet.Disabled == 0)
    for a in fleet:
        # generate a new list of tuples
        fleetList.append((a.VehicleId, a.BusNumberPlate))
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


@server.route("/trip/tripinsert", methods=["POST"])
def addTrip():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "manager":
        formTrip = tripInsert()
        employeeList = getFresh_Employee()
        fleetList = getFresh_Fleet()
        formTrip.EmployeeID.choices = employeeList
        formTrip.VehicleID.choices = fleetList
        if request.method == "POST" and formTrip.validate_on_submit():
            EmployeeID = formTrip.EmployeeID.data
            VehicleID = formTrip.VehicleID.data
            Origin = formTrip.Origin.data
            Destination = formTrip.Destination.data
            StartTime = formTrip.StartTime.data
            EndTime = formTrip.EndTime.data
            TripStatus = formTrip.TripStatus.data
            Disabled = 0
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
                Disabled,
            )
            db.session.add(trip_data)

            # If an invalid character was used in any input field
            try:
                db.session.commit()
            except:
                flash(
                    "At least 1 input field contains an invalid character. Please try again."
                )
                return redirect("/trip")

            obj = db.session.query(Trip).order_by(Trip.TripID.desc()).first()
            logger_crud.info(
                f"Trip (ID: {obj.TripID}) inserted to Trip by Employee (ID: {current_user.EmployeeId})."
            )
            flash("Trip inserted sucessfully")
            return redirect("/trip")

        else:
            logger_crud.warning(
                f"Trip insert failed by Employee (ID: {current_user.EmployeeId})."
            )
            flash("Trip insert failed.")
            return redirect("/trip")

    else:
        return redirect("/notauthorized")


@server.route("/trip/tripSearch", methods=["POST"])
def tripSearch():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    searchformTrip = SearchFormTrip()
    posts = Trip.query
    if current_user.Role.value == "manager":
        if request.method == "POST" and searchformTrip.validate_on_submit():
            postsearched = searchformTrip.searched.data
            searchformTrip.searched.data = ""
            logger_crud.info(
                f"[{postsearched}] searched in trip by Employee (ID: {current_user.EmployeeId})."
            )
            # If an invalid character was used in any search query field
            try:
                posts = posts.filter(Trip.TripID.like("%" + postsearched + "%"))
                posts = posts.order_by(Trip.TripID).all()
            except:
                posts = 0
                flash(
                    "At least 1 input field contains an invalid character. Please try again."
                )
                return render_template(
                    "trip.html",
                    searchformTrip=searchformTrip,
                    searched=postsearched,
                    posts=posts,
                )

            # posts returns empty list if no results found
            if len(posts) == 0:
                posts = 0
                logger_crud.warning(
                    f"No results found in trip search by Employee (ID: {current_user.EmployeeId})."
                )

            if posts != 0:
                return render_template(
                    "trip.html",
                    searchformTrip=searchformTrip,
                    searched=postsearched,
                    posts=posts,
                )
            else:
                flash("Cannot find Trip")
                return render_template(
                    "trip.html",
                    searchformTrip=searchformTrip,
                    searched=postsearched,
                    posts=posts,
                )

    elif current_user.Role.value == "driver":
        if request.method == "POST" and searchformTrip.validate_on_submit():
            postsearched = searchformTrip.searched.data
            searchformTrip.searched.data = ""
            driver_data = (
                Driver.query.filter(Driver.EmployeeId == current_user.EmployeeId)
                .first()
                .DriverId
            )

            # If an invalid character was used in any search query field
            try:
                posts = posts.filter(
                    Trip.TripID.like("%" + postsearched + "%"),
                    Trip.DriverID == driver_data,
                )
                posts = posts.order_by(Trip.TripID).all()
                logger_crud.info(
                    f"[{postsearched}] searched by Employee (ID: {current_user.EmployeeId})."
                )
            except:
                posts = 0
                flash(
                    "At least 1 input field contains an invalid character. Please try again."
                )
                return render_template(
                    "trip.html",
                    searchformTrip=searchformTrip,
                    searched=postsearched,
                    posts=posts,
                )

            # posts returns empty list if no results found
            if len(posts) == 0:
                posts = 0
                logger_crud.warning(
                    f"No results found in trip search by Employee (ID: {current_user.EmployeeId})."
                )

            if posts != 0:
                return render_template(
                    "trip.html",
                    searchformTrip=searchformTrip,
                    searched=postsearched,
                    posts=posts,
                )
            else:
                flash("Cannot find Trip")
                return render_template(
                    "trip.html",
                    searchformTrip=searchformTrip,
                    searched=postsearched,
                    posts=posts,
                )

    else:
        return redirect("/notauthorized")


@server.context_processor
def trip():
    tripupdate = tripInsert()
    return dict(tripupdate=tripupdate)


@server.route("/trip/tripUpdate", methods=["GET", "POST"])
def tripUpdate():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "manager":
        tripupdate = tripInsert()
        if request.method == "POST" and tripupdate.validate_on_submit:
            tID = request.form.get("TripID")
            trip_data = Trip.query.get(request.form.get("TripID"))
            trip_data.DriverID = request.form["DriverID"]
            trip_data.VehicleID = request.form["VehicleID"]
            trip_data.Origin = request.form["Origin"]
            trip_data.Destination = request.form["Destination"]
            trip_data.StartTime = request.form["StartTime"]
            trip_data.EndTime = request.form["EndTime"]
            trip_data.TripStatus = request.form["TripStatus"]

            # If trip is unable to be updated
            try:
                db.session.commit()
            except:
                flash("Trip is unable to be updated. Please try again.")
                logger_crud.error(
                    f"Trip (ID: {id}) update failed by Employee (ID: {current_user.EmployeeId})."
                )
                return redirect("/trip")

            logger_crud.info(f"Trip (ID: {tID}) was updated in Trip.")
            flash("Trip Updated Successfully")
            return redirect(url_for("trip", tripupdate=tripupdate))

    else:
        return redirect("/notauthorized")


@server.route("/trip/delete/<id>", methods=["GET", "POST"])
def tripDelete(id):
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    if current_user.Role.value == "manager":
        if request.method == "GET":
            trip_data = Trip.query.get(id)
            # if trip_data.Disabled == 1:
            #     trip_data.Disabled = 0
            #     logger_crud.info(f"Trip (ID: {id}) ENABLED in Trip.")
            #     flash("Trip enabled sucessfully.")
            # else:
            #     trip_data.Disabled = 1
            #     logger_crud.info(f"Trip (ID: {id}) Disabled in Trip.")
            #     flash("Trip disabled sucessfully.")

            # If Trip is unable to be deleted
            try:
                db.session.delete(trip_data)
                db.session.commit()
            except:
                flash("Trip is unable to be deleted. Please try again.")
                return redirect(url_for("trip"))

            logger_crud.info(
                f"Trip (ID: {id}) update failed by Employee (ID: {current_user.EmployeeId})."
            )
            flash("Trip deleted sucessfully.")
            return redirect(url_for("trip"))
    else:
        return redirect("/notauthorized")


# ----- TRIPS END -----------------------------------------------------------------------
# ----- PROFILE INFO --------------------------------------------------------------------


@server.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    try:
        if current_user.Role.value != None:
            pass
    except:
        return redirect("/login")
    updateFormEmployee = employeeUpdate()
    id = current_user.EmployeeId
    name_to_update = Employee.query.get_or_404(id)
    if request.method == "POST" and updateFormEmployee.validate_on_submit:
        name_to_update.FullName = request.form["FullName"]
        name_to_update.Email = request.form["Email"]
        name_to_update.ContactNumber = request.form["ContactNumber"]
        name_to_update.DOB = request.form["DOB"]

        # Need to check for Emoji
        derived_password = ProcessPassword(
            request.form["OldPassword"], name_to_update.PasswordSalt
        )
        if name_to_update.Password == derived_password:
            if request.form["ConfirmPassword"] == request.form["NewPassword"]:
                PasswordSalt = GenerateCSPRNGToken()  # 32-byte salt in hexadecimal
                is_common_password = CheckCommonPassword(request.form["NewPassword"])

                # If password chosen is a common password
                if is_common_password:
                    flash(
                        "Password chosen is a commonly used password. Please choose another.",
                        "error",
                    )
                    logger_auth.info(
                        f"Common Password attempted when updating profile by EmployeeID (ID: {id})."
                    )
                else:
                    # Need to check for Emoji
                    NewPassword = ProcessPassword(
                        request.form["NewPassword"], PasswordSalt
                    )
                    name_to_update.Password = NewPassword
                    name_to_update.PasswordSalt = PasswordSalt

                    # If an invalid character was used in any input field
                    try:
                        db.session.commit()
                    except:
                        flash(
                            "At least 1 input field contains an invalid character. Please try again."
                        )
                        logger_crud.warning(
                            f"Profile update failed by EmployeeID: {current_user.EmployeeId}."
                        )

                        return render_template(
                            "profile.html",
                            updateFormEmployee=updateFormEmployee,
                            name_to_update=name_to_update,
                        )

                    logger_auth.info(
                        f"Employee (ID: {id}) was updated in Employee by EmployeeID: {current_user.EmployeeId}."
                    )
                    logger_crud.info(
                        f"Employee (ID: {id}) was updated in Employee by EmployeeID: {current_user.EmployeeId}."
                    )
                    flash("Profile has been updated")
                    return render_template(
                        "profile.html",
                        updateFormEmployee=updateFormEmployee,
                        name_to_update=name_to_update,
                    )

            else:
                logger_auth.info(
                    f"Password re-used when updating profile by Employee (ID: {id})."
                )
                flash("Does not match new password or confirm password")
        else:
            logger_auth.warning(
                f"Password is incorrect when updating profile by Employee (ID: {id})."
            )
            flash("Password Incorrect")
    return render_template(
        "profile.html",
        updateFormEmployee=updateFormEmployee,
        name_to_update=name_to_update,
    )


# ----- END PROFILE INFO ---------------------------------------------------------------


if __name__ == "__main__":
    server.run(debug=True)
    db.session.commit()
