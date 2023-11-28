# Django REST Framework TOTP

This app project has a reusable app which can be used to create OTP login. Currently it supports JWT based authentication using the simple JWT library.

The TOTP is generated using PyOTP library.

The app provides two APIs:

### 1) Generate TOTP
<b>Endpoint</b>: /login/otp/generate/

This endpoint generates an OTP and returns the request ID.

### 2) Verify TOTP
<b>EndPoint</b>: /login/otp/verify/

This endpoint takes in two paramters, request id and OTP. It returns access token and refresh token if OTP is valid.