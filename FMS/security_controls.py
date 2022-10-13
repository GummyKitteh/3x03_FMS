import secrets, binascii, os
from backports.pbkdf2 import pbkdf2_hmac

"""
Generate CSPRNG 32-byte salt in hexadecimal based on PEP 506
https://docs.python.org/3/library/secrets.html#secrets.token_bytes
"""
def generate_salt():
	# binascii.hexlify(secrets.token_bytes(32)).decode("utf-8", "strict")
	csprng_salt = secrets.token_bytes(32)
	hex_salt = binascii.hexlify(csprng_salt).decode("utf-8", "strict")
	return hex_salt	# 64 characters


"""
Passwords set shall be validated against a security list (SecList) of common passwords
SecList: https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt
"""
def secure_password(password):
	print("secure_password", password)
	filepath = os.getcwd() + "\\10-million-password-list-top-1000000.txt"
	with open(filepath, "r") as file:
		if password in file.read():
			return True
		return False


"""
Passwords must be uniquely salted for each user with 256 bits, hashed with SHA-256 and iterated 64,000 times with PBKDF2.
https://cryptobook.nakov.com/mac-and-key-derivation/pbkdf2
"""
def process_password(password, salt):
	# Encode password to bytes in utf-8
	password = password.encode("utf-8", "strict")

	# Convert salt to bytes
	salt = binascii.unhexlify(salt)

	# Run through pbkdf2_hmac function
	output = pbkdf2_hmac("sha256", password, salt, 64000, 32)
	
	# Convert to Hex data & decode
	derived_password = binascii.hexlify(output).decode("utf-8", "strict")
	return derived_password

