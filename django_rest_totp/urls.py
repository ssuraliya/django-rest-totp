from django.urls import path

from .views import OTPGenerateViewStore, OTPVerifyViewStore, UserTokenRefreshView

urlpatterns = [
    path(
        "login/otp/generate/",
        OTPGenerateViewStore.as_view(),
        name="otp-generate",
    ),
    path(
        "login/otp/verify/",
        OTPVerifyViewStore.as_view(),
        name="otp-verify",
    ),
    path(
        "login/refresh/",
        UserTokenRefreshView.as_view(),
        name="user-token-refresh",
    ),
]
