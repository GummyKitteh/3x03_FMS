import secrets, binascii, os, jwt, base64
from hashlib import pbkdf2_hmac
from datetime import datetime, timezone, timedelta

"""
Generate CSPRNG 32-byte salt in hexadecimal based on PEP 506
https://docs.python.org/3/library/secrets.html#secrets.token_bytes
"""
def generate_csprng_token():
	csprng_salt = secrets.token_bytes(32)
	hex_salt = binascii.hexlify(csprng_salt).decode("utf-8", "strict")

	# Check if salt exists in database if possble:

	return hex_salt	# 64 characters


"""
Passwords set shall be validated against a security list (SecList) of common passwords
SecList: https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt
"""
def check_common_password(password):
	filepath = os.getcwd() + "\\10-million-password-list-top-1000000.txt"
	with open(filepath, "r") as file:
		if password in file.read():
			return True
		return False


"""
Passwords must be uniquely salted for each user with 256 bits, hashed with SHA-256 and iterated 310,000 times with PBKDF2.
https://cryptobook.nakov.com/mac-and-key-derivation/pbkdf2
"""
def process_password(password, hex_salt):
	# Encode password to bytes in utf-8
	password = password.encode("utf-8", "strict")

	# Convert salt to bytes
	salt = binascii.unhexlify(hex_salt)

	# Run through pbkdf2_hmac function
	output = pbkdf2_hmac("sha256", password, salt, 64000, 32)
	# replace with this: output = pbkdf2_hmac("sha256", password, salt, 310000, 32)
	
	# Convert to Hex data & decode
	derived_password = binascii.hexlify(output).decode("utf-8", "strict")
	return derived_password


"""
Encoding password reset tokens with PyJWT, and must be unique and not easily guessable.
https://pyjwt.readthedocs.io/en/latest/usage.html
"""
def generate_reset_token(userid):
	token_issued = datetime.now(tz=timezone.utc)
	token_expiry = token_issued + timedelta(hours=1)
	jwt_payload = {
		"reset_token": userid,
		"iat": token_issued,
		"exp": token_expiry}
	jwt_encode = jwt.encode(
		jwt_payload,
		key="I really hope fking this work if never idk what to do :(",
		algorithm="HS256").encode("utf-8", "strict")

	# TODO: Update key to point to Config file.

	return base64.urlsafe_b64encode(jwt_encode).decode("utf-8", "strict")


"""
Decoding password reset tokens with PyJWT, and must be unique and not easily guessable.
https://pyjwt.readthedocs.io/en/latest/usage.html
"""
def decode_reset_token(token):
	jwt_token = base64.urlsafe_b64decode(token).decode("utf-8", "strict")
	return jwt.decode(
		jwt_token,
		key="I really hope fking this work if never idk what to do :(",
		algorithms="HS256")

	# TODO: Update key to point to Config file.

