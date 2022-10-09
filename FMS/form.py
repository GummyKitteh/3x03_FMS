from logging import PlaceHolder
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    SubmitField,
    DateField,
    SelectField,
    IntegerField,
    TimeField,
    PasswordField,
)
from wtforms.validators import DataRequired, Length, Email
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
        "Search:", [DataRequired()], render_kw={"placeholder": "employee name"}
    )
    submit = SubmitField("Submit")


class SearchFormFleet(FlaskForm):
    searched = StringField(
        "Search Vehicle:", [DataRequired()], render_kw={"placeholder": "Search"}
    )
    submit = SubmitField("Submit")


class SearchFormTrip(FlaskForm):
    searched = StringField(
        "Search Trip:", [DataRequired()], render_kw={"placeholder": "Search"}
    )
    submit = SubmitField("Submit")


class employeeInsert(FlaskForm):
    FullName = StringField("Full Name", [DataRequired(), Length(max=50)])
    Email = StringField("Email", [DataRequired(), Email(), Length(max=100)])
    ContactNumber = StringField(
        "Contact Number", [DataRequired(), Length(min=8), Length(max=8)]
    )
    DOB = DateField("DOB", format="%Y-%m-%d")
    Role = SelectField(
        "Role", choices=[(choice.name, choice.value) for choice in RoleTypes]
    )
    Password = PasswordField("Password", [DataRequired(), Length(min=8)])
    submit = SubmitField("Submit", [DataRequired()])


class fleetInsert(FlaskForm):
    BusNumberPlate = StringField("Number Plate", [DataRequired(), Length(max=8)])
    VehicleCapacity = IntegerField("Vehicle Capacity", [DataRequired()])
    VehicleStatus = StringField("Vehicle Status", [DataRequired(), Length(max=20)])
    submit = SubmitField("Submit", [DataRequired()])


# class tripInsert(FlaskForm):
#     # EmployeeID = IntegerField("Employee ID", [DataRequired()])
#     EmployeeID = SelectField(query_factory=lambda: Employee.query.all())
#     VehicleID = IntegerField("Vehicle ID", [DataRequired()])
#     Origin = StringField("Origin", [DataRequired(), Length(max=256)])
#     Destination = StringField("Destination", [DataRequired(), Length(max=256)])
#     StartTime = DateField("Start Time")
#     EndTime = DateField("End Time")
#     TripStatus = SelectField(
#         "Status", choices=[(choice.name, choice.value) for choice in TripStatusTypes]
#     )
#     submit = SubmitField("Submit", [DataRequired()])


class LoginForm(FlaskForm):
    Email = StringField("Email", [DataRequired(), Email(), Length(max=100)])
    password = PasswordField("Password: ", [DataRequired(), Length(max=50)])
    submit = SubmitField("Login")
