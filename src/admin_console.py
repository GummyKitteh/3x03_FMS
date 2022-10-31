import secrets, binascii
from hashlib import pbkdf2_hmac

temp_password = "temp@password"

# Generate Salt
csprng_salt = secrets.token_bytes(32)
hex_salt = binascii.hexlify(csprng_salt).decode("utf-8", "strict")

password = temp_password.encode("utf-8", "strict")
salt = binascii.unhexlify(hex_salt)
output = pbkdf2_hmac("sha256", password, salt, 310000, 32)
derived_password = binascii.hexlify(output).decode("utf-8", "strict")

print("=========================\nIn Case Of Locked Account\n=========================")
print("Update the following in the database for the correct Employee:")
print("AccountLocked: 0")
print("Password:", derived_password)
print("PasswordSalt:", hex_salt)
print("LoginCounter: 0")
print("ResetFlag: 0")
print("\n===========================================\nThen, Inform the Employee the temp password\n===========================================")