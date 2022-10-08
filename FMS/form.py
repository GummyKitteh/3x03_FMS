from logging import PlaceHolder
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, DateField, SelectField
from wtforms.validators import DataRequired, Length, Email
from enum import Enum


class RoleTypes(Enum):
    admin = "admin"
    manager = "manager"
    driver = "driver"


class SearchFormEmployee(FlaskForm):
    searched = StringField(
        "Search:", [DataRequired()], render_kw={"placeholder": "Search"}
    )
    submit = SubmitField("Submit")


class SearchFormFleet(FlaskForm):
    searched = StringField(
        "Search Vehicle:", [DataRequired()], render_kw={"placeholder": "Search"}
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
    Password = StringField("Password", [DataRequired(), Length(min=8)])
    submit = SubmitField("Submit", [DataRequired()])


class fleetInsert(FlaskForm):
    BusNumberPlate = StringField("Number Plate", [DataRequired(), Length(max=8)])
    VehicleCapacity = StringField("Vehicle Capacity", [DataRequired(), Length(max=10)])
    VehicleStatus = StringField("Vehicle Status", [DataRequired(), Length(max=20)])
    submit = SubmitField("Submit", [DataRequired()])
