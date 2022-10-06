from logging import PlaceHolder
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, DateField,  SelectField
from wtforms.validators import DataRequired, Length, Email
from enum import Enum

class datainsert(FlaskForm):
    name = StringField("Name",[DataRequired(),Length(max=50)])
    email = StringField("Email",[DataRequired(),Email(), Length(max=100)])
    phone = StringField("Phone",[DataRequired(), Length(min=8), Length(max=8)])
    submit = SubmitField("Submit")

class SearchFormEmployee(FlaskForm):
    searched = StringField("Search:",[DataRequired()], render_kw={"placeholder": "Search"})
    submit = SubmitField("Submit")

    # EMPLOYEE Classes
class RoleTypes(Enum):
    admin = "admin"
    manager = "manager"
    driver = "driver"

class employeeInsert(FlaskForm):
    FullName = StringField("Full Name", [DataRequired(), Length(max=50)])
    Email = StringField("Email", [DataRequired(), Email(), Length(max=100)])
    ContactNumber = StringField(
        "Contact Number", [DataRequired(), Length(min=8), Length(max=8)]
    )
    DOB = DateField("DOB", format='%Y-%m-%d')
    Role = SelectField(
        "Role", choices=[(choice.name, choice.value) for choice in RoleTypes]
    )
    Password = StringField("Password", [DataRequired(), Length(min=8)])
    submit = SubmitField("Submit", [DataRequired()])
