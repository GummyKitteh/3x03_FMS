from logging import exception
from flask import Flask, render_template,request, redirect, url_for
from flask_mysqldb import MySQL

app = Flask(__name__)
app.secret_key= "abcd"

# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql:+pymysql//root:Barney-123@localhost/fmssql.db'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Barney-123'
app.config['MYSQL_DB'] = 'fmssql'
mysql = MySQL(app)
#Creating a connection cursor
with app.app_context():
    cursor = mysql.connection.cursor()
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/insert', methods=['POST'])
def insert():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        try:
            cursor.execute('USE fmssql')
            cursor.execute('''INSERT INTO test (name,email,phone)VALUES (%s,%s,%s)''',(name,email,phone))
            results = cursor.fetchall()
            mysql.connection.commit()
            cursor.close()
            return "NOOOO"

        except:
            return exception

    else:
        return "Nil"
if __name__ == "__main__":
    app.run(debug=True)


        