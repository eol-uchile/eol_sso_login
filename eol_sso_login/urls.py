from django.contrib import admin
from django.conf.urls import url
from django.contrib.admin.views.decorators import staff_member_required
from .views import *
from .api import registration_validation, check_email

urlpatterns = [
    url(r'^eol_sso_login/uchile_login/$', SSOLoginUChileRedirect.as_view(), name='uchile_login'),
    url(r'^eol_sso_login/uchile_callback/$', SSOLoginUChileCallback.as_view(), name='uchile_callback'),
    url(r'^eol_sso_login/api/registration/$', registration_validation, name="api-registration"),
    url(r'^eol_sso_login/api/email/$', check_email, name="api-email"),
    url(r'^sso/verification$', SSOLoginUChileVerification.as_view(), name='verification'),
    url(r'^sso/verification_form$', SSOLoginUChileVerificationData.as_view(), name='verification-data'),
    url(r'^sso/verification_pending$', SSOLoginUChileVerificationPending.as_view(), name='verification-pending'),
]
