from decouple import config

OTP_EXPIRE_INTERVAL = config("OTP_EXPIRE_INTERVAL", 600)
RESEND_OTP_ALLOWED_AFTER_MINS = config("RESEND_OTP_ALLOWED_AFTER_MINS", 1)
