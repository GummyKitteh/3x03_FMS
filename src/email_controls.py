from flask_mail import Message
import os
from datetime import datetime
from threading import Thread
from security_controls import GenerateJWTToken


# Set some variables
def EmailRole(role):
    if role == "driver":
        administrator = "the IT Administrator"
        supervisor = "your Manager or IT Administrator"
    elif role == "manager":
        administrator = "the IT Administrator"
        supervisor = "the IT Administrator"
    else:
        administrator = "an IT Administrator"
        supervisor = "an IT Administrator"
    return administrator, supervisor


# Applicable Methods to Send Email without a time limit:
# login(): "login-locked-disabled" (Account Locked / Disabled)
# login(): "login-admin" (Account Locked)
# send_otp(): "send-otp" (Send OTP)
# postPassword(): "new-password" (Password Changed)
def EmailNotificationUntimed(db, server, email_service, user, message):
    # Craft email object
    email = Message()
    email.recipients = [user.Email]

    # 1. Send email to notify User if accumulated 5 invalid attempts
    # 2. Send email to notify User if NOT notified of account lock or disable in the last 10 minutes
    if message == "login-locked-disabled":
        administrator, supervisor = EmailRole(user.Role)
        email.subject = "You Account Has Been Locked or Disabled"
        email.body = "Dear {},\n\nWe note that you have attempted to log in to your Bus FMS account without success.\nUnfortunately, your account has either been locked after too many invalid login attempts, or it has been disabled by {}.\n\nPlease contact {} for assistance.\n\nThank you for your continued support in Bus FMS.\n\nBest regards,\nBus FMS".format(
            user.FullName, administrator, supervisor
        )

    # Send email to notify Administrator if user accumulated 5 invalid attempts
    elif message == "login-admin":
        mail_user = os.getenv("mail_user")
        email.recipients = [mail_user]
        email.subject = "Employee ID {}: Account Has Been Locked".format(user.EmployeeId)
        email.body = "Dear IT Administrator,\n\nAn account has been locked following 5 invalid login attempts.\n\nEmployee ID: {}\n\nYou may wish to contact the user to assist.\nThank you.\n\nBest regards,\nBus FMS".format(
            user.EmployeeId
        )

    # Send email to notify User the requested OTP
    elif message == "send-otp":
        email.subject = "Your Bus FMS OTP"
        email.body = "Dear {}, \n\nYour OTP is {}.\nPlease note that your OTP is only valid for 2 minutes.\n\nThank you for your continued support in Bus FMS.\n\nBest regards,\nBus FMS".format(
            user.FullName, user.OTP
        )

    # Send Email to notify User that Password has been changed
    elif message == "new-password":
        administrator, supervisor = EmailRole(user.Role)
        email.subject = "Your Bus FMS Password Has Been Changed"
        email.body = "Dear {},\n\nYour Bus FMS password has just been changed.\n\nIf you did not perform this request, please contact {} as soon as possible.\n\nThank you for your continued support in Bus FMS.\n\nBest regards,\nBus FMS".format(
            user.FullName, supervisor
        )

    # Send email object
    Thread(target=SendEmail, args=(server, email_service, email)).start()


# Applicable Methods to Send Email if outside of 1 hour time limit:
# reset(): "reset-locked" (Account Locked) w/o Reset Link
# reset(): "reset-not-locked" (Request Password Reset) w/ Reset Link
# login(): "login-welcome" (First Login) w/ Reset Link
# employeeDelete(): "Re-Enabled" (Account Enabled) w/ & w/o Reset Link
# employeeUnlock(): "Unlocked" (Account Unlocked) w/ & w/o Reset Link
def EmailNotificationTimed(db, server, email_service, user, message):
    # Craft email object
    email = Message()
    email.recipients = [user.Email]

    # Calculate time delta between current time and last sent email
    try:
        # If there is a timestamp in user.ResetDateTime
        email_token_delta = (
            datetime.utcnow() - user.ResetDateTime
        ).total_seconds()
        delta_hour = email_token_delta // 3600
    except:
        # If there is no timestamp in user.ResetDateTime
        delta_hour = 1

    # If user has NOT been sent a Reset Link in the last 1 hour
    if delta_hour >= 1:

        # Update ResetDateTime to prevent user email spam
        user.ResetDateTime = datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # Send email w/o Reset Link if user account is locked (after 5 invalid attempts)
        if message == "reset-locked":
            administrator, supervisor = EmailRole(user.Role)
            email.subject = "Password Reset Link"
            email.body = "Dear {},\n\nYou have requested a password reset for your Bus FMS account.\n\nUnfortunately, your account has been locked after too many invalid attempts.\nPlease contact {} for assistance.\n\nThank you for your continued support in Bus FMS.\n\nBest regards,\nBus FMS".format(
                user.FullName, supervisor
            )

        # Send email w/ Reset Link
        elif message == "login-welcome" or message == "reset-not-locked" or message == "Re-Enabled" or message == "Unlocked":

            # Generate JWT Reset Token (output in Base64) for password reset
            email_token = GenerateJWTToken(user.get_id(), "reset")
            user.ResetFlag = 1  # 1 means Reset Link is STILL VALID & has not been used

            # Craft email body with Reset Link
            reset_link = "http://localhost:5000/new-password/{}".format(
                email_token
            )
            # reset_link = "http://busfms.tk/new-password/{}".format(email_token)

            # If user account is NOT locked
            if message == "reset-not-locked":
                email.subject = "Password Reset Link"
                email.body = "Dear {},\n\nYou have requested a password reset for your Bus FMS account.\n\nKindly click on the link below, or copy it into your trusted Web Browser (i.e. Google Chrome), to do so.\nPlease note that the link is only valid for 1 hour.\n\nLink: {}\n\nYou may ignore this email if you did not make this request.\nRest assure that your account has not been compromised, and your information is safe with us!\n\nThank you for your continued support in Bus FMS.\n\nBest regards,\nBus FMS".format(
                    user.FullName, reset_link
                )

            # If user has never logged in before (i.e. First login)
            elif message == "login-welcome":
                email.subject = "Welcome To Bus FMS!"
                email.body = "Dear {},\n\nAs our valued partner, you are requested to create your first password before you can access our features.\n\nKindly click on the link below, or copy it into your trusted Web Browser (i.e. Google Chrome), to do so.\nPlease note that the link is only valid for 1 hour.\n\nLink: {}\n\nThank you for your support in Bus FMS. We hope you will have a pleasant experience with us!\n\nBest regards,\nBus FMS".format(
                    user.FullName, reset_link
                )

            # If user account is Enabled/Unlocked by an Administrator
            else:
                email.subject = "Your Bus FMS Account Has Been {}".format(message)
                email.body = "Dear {},\n\nYour Bus FMS account has just been {} by our IT Administrator.\n\nYou may continue to use your current/existing password if you still remember it.\nAlternatively, you may reset your password using the link below.\n\nKindly click on the link, or copy it into your trusted Web Browser (i.e. Google Chrome), to reset your password.\nPlease note that the link is only valid for 1 hour.\n\nLink: {}\n\nThank you for your continued support in Bus FMS.\n\nBest regards,\nBus FMS".format(
                    user.FullName, message, reset_link
                )

            db.session.commit()

            # Send email object
            Thread(target=SendEmail, args=(server, email_service, email)).start()

    # Else user HAS requested / been sent a Reset Link in the last 1 hour
    else:
        if message == "Re-Enabled" or message == "Unlocked":
            email.body = "Dear {},\n\nYour Bus FMS account has just been {} by our IT Administrator.\n\nYou may continue to use your current/existing password if you still remember it.\n\nAlternatively, we note that you have requested for a Password Reset Link in the last 1 hour.\nKindly wait for the 1 hour buffer to end, as you may only request for a new Password Reset once an hour.\n\nThank you for your continued support in Bus FMS.\n\nBest regards,\nBus FMS".format(
                user.FullName, message
            )
            # Send email object
            Thread(target=SendEmail, args=(server, email_service, email)).start()


# Method to send email objects, initiated from a Thread
def SendEmail(server, email_service, email):
    with server.app_context():
        email_service.send(email)
