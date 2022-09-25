from App import db

# class Data(db.Model):
#     id = db.Column(db.Integer, primary_key = True)
#     name = db.Column(db.String(100))
#     email = db.Column(db.String(100))
#     phone = db.Column(db.String(100))
class Data(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(100))

    def __init__(self,name,email,phone):
        self.name = name
        self.email = email
        self.phone = phone

class employee(db.Model):
    EmployeeID = db.Column(db.Integer, primary_key = True)
    FullName = db.Column(db.String(256))
    Email = db.Column(db.String(256))
    ContactNumber = db.Column(db.Integer)
    Role = db.Column(db.Enum('admin','manager','driver'))
    Password = db.Column(db.String(256))
    AccountLocked = db.Column(db.Integer)

    def __init__(self,FullName,Email,ContactNumber,Role,AccountLocked,Password):
        self.FullName = FullName
        self.Email = Email
        self.ContactNumber = ContactNumber
        self.Role = Role
        self.AccountLocked = AccountLocked
        self.Password = Password