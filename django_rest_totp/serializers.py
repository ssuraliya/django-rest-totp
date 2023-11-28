from datetime import datetime, timedelta, timezone

import pyotp
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.transaction import atomic
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken

from .constants import OTP_EXPIRE_INTERVAL, RESEND_OTP_ALLOWED_AFTER_MINS
from .models import TOTPStore

UserModel = get_user_model()


def get_totp_cache_key(user):
    return f"totp-store-cache-{user.pk}"


class OTPGenerateSerializer(serializers.Serializer):
    username_field = UserModel.USERNAME_FIELD

    request_id = serializers.CharField(read_only=True)

    default_error_messages = {"no_active_account": "No active account found."}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields[self.username_field] = serializers.CharField()

    def get_user(self, username_value):
        """
        Fetching user by the username field of the UserModel. Override to apply
        any logic to not allow user.
        """
        try:
            user = UserModel._default_manager.get_by_natural_key(username_value)
        except:
            raise AuthenticationFailed(
                self.error_messages["no_active_account"],
                "no_active_account",
            )
        return user

    def can_send_otp(self, otp_sent_at):
        if otp_sent_at:
            time_diff = datetime.now(tz=timezone.utc) - otp_sent_at
            if time_diff.total_seconds() < RESEND_OTP_ALLOWED_AFTER_MINS * 60:
                return False
        return True

    def send_otp_to_user(self, otp, user):
        """
        Invoke a celery task or write a logic to dispatch OTP to user.
        This function will only be called if the generation request if sent
        after RESEND_OTP_ALLOWED_AFTER_MINS.
        """
        pass

    def _generate_otp(self, user):
        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(s=totp_secret, digits=6, interval=OTP_EXPIRE_INTERVAL)

        valid_till = datetime.now(tz=timezone.utc) + timedelta(
            seconds=OTP_EXPIRE_INTERVAL
        )

        totp_store = TOTPStore.objects.create(
            user=user,
            secret=totp_secret,
            valid_till=valid_till,
            verified=False,
        )
        user.refresh_from_db()
        return totp.now(), totp_store

    def _update_cache_data(self, cached_data, otp, totp_store):
        if cached_data is None:
            cached_data = {
                "otp": otp,
                "totp_store": totp_store,
                "otp_sent_at": datetime.now(tz=timezone.utc),
            }
        else:
            cached_data["otp"] = otp
            cached_data["totp_store"] = totp_store
        return cached_data

    @atomic
    def validate(self, attrs):
        user = self.get_user(attrs[self.username_field])

        cache_key = get_totp_cache_key(user)

        cached_data = cache.get(cache_key, None)

        if cached_data and cached_data["totp_store"].valid_till > datetime.now(
            tz=timezone.utc
        ):
            totp_store = cached_data["totp_store"]
            otp = cached_data["otp"]
        else:
            otp, totp_store = self._generate_otp(user)

        last_sent = cached_data.get("otp_sent_at", None) if cached_data else None

        cached_data = self._update_cache_data(cached_data, otp, totp_store)

        if self.can_send_otp(last_sent):
            self.send_otp_to_user(otp, user)
            cached_data["otp_sent_at"] = datetime.now(tz=timezone.utc)

        cache.set(cache_key, cached_data)

        attrs["request_id"] = str(totp_store.uuid)

        return attrs


class OTPVerifySerializer(serializers.Serializer):
    request_id = serializers.SlugRelatedField(
        allow_null=False,
        slug_field="uuid",
        queryset=TOTPStore.objects.all(),
        required=True,
        write_only=True,
    )
    otp = serializers.CharField(
        write_only=True, allow_null=False, allow_blank=False, required=True
    )
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)

    def is_totp_valid(self, totp_store, otp):
        current_datetime = datetime.now(tz=timezone.utc)

        if totp_store.valid_till < current_datetime or totp_store.verified:
            return False

        totp_secret = totp_store.secret

        totp = pyotp.TOTP(s=totp_secret, digits=6, interval=OTP_EXPIRE_INTERVAL)
        return totp.verify(otp)

    def register_totp_used(self, totp_store):
        totp_store.verified = True
        totp_store.save()

        cache_key = get_totp_cache_key(totp_store.user)

        cache.delete(cache_key)

    def get_token(self, user):
        refresh = RefreshToken.for_user(user)

        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }

    @atomic
    def validate(self, attrs):
        totp_store = attrs["request_id"]
        otp = attrs["otp"]

        if not self.is_totp_valid(totp_store, otp):
            raise DjangoValidationError(
                "Invalid OTP",
                code="invalid_otp",
            )

        self.register_totp_used(totp_store)

        return self.get_token(totp_store.user)
