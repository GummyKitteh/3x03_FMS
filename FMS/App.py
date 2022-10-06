from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from torch import equal
from form import datainsert, SearchFormEmployee

app = Flask(__name__)
app.secret_key = "abcd"
app.config['SECRET_KEY'] ="I really hope fking this work if never idk what to do :("

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Barney-123@localhost/fmssql'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:qwerty1234@localhost/fmssql'
#app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:B33pb33p!@178.128.17.35/fmssql"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(100))

    def __init__(self, name, email, phone):
        self.name = name
        self.email = email
        self.phone = phone


@app.route("/")
def index():
    all_data = Data.query.all()
    return render_template("index.html", employees=all_data)
@app.context_processor
def index():
    form = datainsert()
    return dict(form=form)
@app.route("/employeeinsert", methods=["POST"])
def employeeinsert():
    form = datainsert()
    name = None
    email = None
    phone = None
    if request.method == "POST" and form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        phone = form.phone.data
        form.name.data = ''
        form.email.data = ''
        form.phone.data = ''
        my_data = Data(name, email, phone)
        db.session.add(my_data)
        db.session.commit()
        flash("Employee Inserted Sucessfully")
        return redirect("/")
    else:
        flash("Employee Inserted Unsucessfully")
        return redirect("/")
    
@app.route("/update", methods=["GET","POST"])
def update():
    if request.method == "POST":
        my_data = Data.query.get(request.form.get("id"))
        my_data.name = request.form["name"]
        my_data.email = request.form["email"]
        my_data.phone = request.form["phone"]

        db.session.commit()
        flash("Employee Updated Successfully")

        return redirect(url_for("index"))



@app.route("/delete/<id>/", methods=["GET", "POST"])
def delete(id):
    if request.method == "GET":
        my_data = Data.query.get(id)
        db.session.delete(my_data)
        db.session.commit()

        flash("Employee Delete Sucessfully")
        return redirect(url_for("index"))
@app.context_processor
def index():
    searchform = SearchFormEmployee()
    return dict(searchform=searchform)
@app.route("/employeesearch",methods=["POST"])
def employeesearch():
    searchform = SearchFormEmployee()
    posts = Data.query
    if request.method == "POST" and searchform.validate_on_submit():
        postsearched = searchform.searched.data
        searchform.searched.data = ''
        posts = posts.filter(Data.name.like('%' + postsearched + '%'))
        posts = posts.order_by(Data.id).all()
        if posts != 0:
            return render_template("index.html", searchform=searchform, searched = postsearched, posts = posts)
        else:
            flash("Cannot find Employee")

@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/reset")
def reset():
    return render_template("reset.html")


if __name__ == "__main__":
    app.run(debug=True)
