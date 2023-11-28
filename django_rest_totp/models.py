import uuid

from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _

AUTH_USER_MODEL = getattr(settings, "AUTH_USER_MODEL", "auth.User")


class TOTPStore(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, unique=True, db_index=True)
    user = models.ForeignKey(
        AUTH_USER_MODEL, related_name="totp_store", on_delete=models.CASCADE, null=False
    )
    secret = models.CharField(max_length=32, null=False, blank=False)
    valid_till = models.DateTimeField(null=False, blank=False)
    verified = models.BooleanField(null=False, default=False)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)
