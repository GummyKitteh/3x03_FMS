from logging import PlaceHolder
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import (
    StringField,
    SubmitField,
    DateField,
    SelectField,
    IntegerField,
    TimeField,
    PasswordField,
)
from flask_login import current_user
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from enum import Enum


class RoleTypes(Enum):
    admin = "admin"
    manager = "manager"
    driver = "driver"


class TripStatusTypes(Enum):
    Inactive = "Inactive"
    Decommission = "Decommission"
    Active = "Active"


class SearchFormEmployee(FlaskForm):
    searched = StringField(
        "Search:",
        [DataRequired()],
        render_kw={"placeholder": "Search by Employee Name"},
    )
    submit = SubmitField("Submit")


class SearchFormFleet(FlaskForm):
    searched = StringField(
        "Search Vehicle:",
        [DataRequired()],
        render_kw={"placeholder": "Search by Number Plate"},
    )
    submit = SubmitField("Submit")


class SearchFormTrip(FlaskForm):
    searched = StringField(
        "Search Trip:", [DataRequired()], render_kw={"placeholder": "Search by TripID"}
    )
    submit = SubmitField("Submit")


class employeeInsert(FlaskForm):
    FullName = StringField("Full Name", [DataRequired(), Length(max=50)])
    Email = StringField("Email", [DataRequired(), Email(), Length(max=100)])
    ContactNumber = StringField(
        "Contact Number", [DataRequired(), Length(min=8, max=8)]
    )
    DOB = DateField("DOB", format="%Y-%m-%d")
    Password = PasswordField("Password", [DataRequired(), Length(min=8)])
    submit = SubmitField("Submit", [DataRequired()])


class employeeUpdate(FlaskForm):
    FullName = StringField("Full Name", [DataRequired(), Length(max=50)])
    Email = StringField("Email", [DataRequired(), Email(), Length(max=100)])
    ContactNumber = StringField(
        "Contact Number", [DataRequired(), Length(min=8, max=8)]
    )
    DOB = DateField("DOB", format="%Y-%m-%d")
    Role = SelectField(
        "Role", choices=[(choice.name, choice.value) for choice in RoleTypes]
    )

    Password = PasswordField("Password", [DataRequired(), Length(min=8)])
    OldPassword = PasswordField("Old Password", [DataRequired(), Length(min=8)])
    NewPassword = PasswordField("New Password", [DataRequired(), Length(min=8)])
    ConfirmPassword = PasswordField("Confirm Password", [DataRequired(), Length(min=8)])
    submit = SubmitField("Submit", [DataRequired()])


class fleetInsert(FlaskForm):
    BusNumberPlate = StringField("Number Plate", [DataRequired(), Length(max=8)])
    VehicleCapacity = IntegerField("Vehicle Capacity", [DataRequired()])
    VehicleStatus = StringField("Vehicle Status", [DataRequired(), Length(max=20)])
    submit = SubmitField("Submit", [DataRequired()])


class LoginForm(FlaskForm):
    Email = StringField("Email", [DataRequired(), Email(), Length(max=100)])
    password = PasswordField("Password", [DataRequired(), Length(max=50)])
    # recaptcha = RecaptchaField()
    submit = SubmitField("Login")


class OTPForm(FlaskForm):
    OTP = PasswordField(
        "OTP", [DataRequired(), Length(min=6, max=6), Regexp(regex="^[0-9]+$")]
    )
    OTPToken = StringField([DataRequired()])
    # recaptcha = RecaptchaField()
    submit = SubmitField("Submit")


class ResendOTPForm(FlaskForm):
    OTPToken = StringField([DataRequired()])
    submit = SubmitField("Request New OTP")


class ResetPasswordForm(FlaskForm):
    Phone = StringField(
        "Contact Number",
        [DataRequired(), Length(min=8, max=8), Regexp(regex="^[0-9]+$")],
    )
    Email = StringField("Email", [DataRequired(), Email(), Length(max=100)])
    # recaptcha = RecaptchaField()
    submit = SubmitField("Reset", [DataRequired()])


class NewPasswordForm(FlaskForm):
    NewPassword = PasswordField("New Password", [DataRequired(), Length(min=8)])
    ConfirmPassword = PasswordField(
        "Confirm Password", [DataRequired(), Length(min=8), EqualTo("NewPassword")]
    )
    EmailToken = StringField([DataRequired()])
    # recaptcha = RecaptchaField()
    submit = SubmitField("Reset", [DataRequired()])
