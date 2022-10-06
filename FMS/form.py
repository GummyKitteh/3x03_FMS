from logging import PlaceHolder
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, Email

class datainsert(FlaskForm):
    name = StringField("Name",[DataRequired(),Length(max=50)])
    email = StringField("Email",[DataRequired(),Email(), Length(max=100)])
    phone = StringField("Phone",[DataRequired(), Length(min=8), Length(max=8)])
    submit = SubmitField("Submit")

class SearchFormEmployee(FlaskForm):
    searched = StringField("Search:",[DataRequired()], render_kw={"placeholder": "Search"})
    submit = SubmitField("Submit")