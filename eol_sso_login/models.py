import uuid  # lint-amnesty, pylint: disable=wrong-import-order

from django.contrib.auth.models import User
from django.db import models
from django.core.exceptions import ValidationError
from opaque_keys.edx.django.models import CourseKeyField
from django.utils.translation import gettext_lazy as _
# Create your models here.

class SSOLoginCuentaUChile(models.Model):
    username = models.CharField(max_length=50, unique=True, db_index=True)
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        blank=False,
        null=False)
    is_active = models.BooleanField(default=False)
    login_timestamp = models.DateTimeField(default=None, null=True, blank=True)

class SSOLoginExtraData(models.Model):
    class Meta:
        index_together = [
            ["document", "type_document"],
        ]
        unique_together = [
            ["document", "type_document"],
        ]
    MODE_CHOICES = (("rut", _("Rut")), ("passport", _("Passport")), ("dni", _("DNI")),)
    document = models.CharField(max_length=21, verbose_name=_("Document"), help_text=_("Document number"))
    type_document = models.CharField(choices=MODE_CHOICES, verbose_name=_("Document type"), help_text=_("Select document type"), max_length=10)
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        blank=False,
        null=False)

class SSOLoginCuentaUChileRegistration(models.Model):
    username = models.CharField(max_length=50, unique=True, db_index=True)
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        blank=False,
        null=False)
    activation_key = models.CharField((u'activation key'), max_length=32, unique=True, db_index=True)
    activation_timestamp = models.DateTimeField(default=None, null=True, blank=True)