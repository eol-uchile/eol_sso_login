
from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
from django.conf import settings

from celery import task
from django.core.mail import send_mail
from django.utils.html import strip_tags
from django.contrib.auth.models import User
from urllib.parse import urlencode
from django.urls import reverse
import unidecode
from django.template.loader import render_to_string
from .models import SSOLoginCuentaUChile, SSOLoginExtraData, SSOLoginCuentaUChileRegistration
import logging
logger = logging.getLogger(__name__)

EMAIL_DEFAULT_RETRY_DELAY = 30
EMAIL_MAX_RETRIES = 5

@task(
    queue='edx.lms.core.low',
    default_retry_delay=EMAIL_DEFAULT_RETRY_DELAY,
    max_retries=EMAIL_MAX_RETRIES)
def enroll_email(data, courses_name, login_url, helpdesk_url, confirmation_url):
    """
        Send mail to specific user
    """
    platform_name = configuration_helpers.get_value('PLATFORM_NAME', settings.PLATFORM_NAME)
    subject = 'Inscripción en el curso: {}'.format(courses_name)
    user = User.objects.get(username=data['username'])
    created = data['created']
    have_sso = SSOLoginCuentaUChile.objects.filter(user=user).exists()
    active_sso = SSOLoginCuentaUChile.objects.filter(user=user, is_active=True).exists()
    diff_email = user.email != data['email']
    ssologin_register = None
    if not active_sso:
        try:
            ssologin_register = SSOLoginCuentaUChileRegistration.objects.get(user=user)
            confirmation_url = '{}?{}'.format(confirmation_url, urlencode({'id':ssologin_register.activation_key}))
        except Exception:
            pass
    context = {
        "courses_name": courses_name,
        "platform_name": platform_name,
        "user_password": data['password'],
        'user_email': user.email,
        'login_url': login_url,
        'user_name': user.profile.name.strip(),
        'helpdesk_url': helpdesk_url,
        'confirmation_url': confirmation_url
    }
    emails = [user.email]
    if diff_email:
        emails.append(data['email'])

    if created:
        if have_sso and active_sso:
            html_message = render_to_string('eol_sso_login/emails/sso.txt', context)
        elif not have_sso:
            html_message = render_to_string('eol_sso_login/emails/normal_pass.txt', context)
        elif have_sso and not active_sso:
            html_message = render_to_string('eol_sso_login/emails/normal_pass.txt', context)
    else:
        if have_sso and active_sso:
            html_message = render_to_string('eol_sso_login/emails/sso.txt', context)
        elif have_sso and not active_sso:
            html_message = render_to_string('eol_sso_login/emails/normal_sso.txt', context)
        elif not have_sso:
            html_message = render_to_string('eol_sso_login/emails/normal.txt', context)
    plain_message = strip_tags(html_message)
    from_email = configuration_helpers.get_value(
        'email_from_address',
        settings.BULK_EMAIL_DEFAULT_FROM_EMAIL
    )
    mail = send_mail(
        subject,
        plain_message,
        from_email,
        emails,
        fail_silently=False,
        html_message=html_message)
    return mail

@task(
    queue='edx.lms.core.low',
    default_retry_delay=EMAIL_DEFAULT_RETRY_DELAY,
    max_retries=EMAIL_MAX_RETRIES)
def merge_verification_email(fullname, user_email, confirmation_url, login_url, helpdesk_url, platform_name):
    """
        Send confirmation mail to connect edxloginuser and user
    """
    subject = 'Verificación de identidad en {}'.format(platform_name)
    context = {
        "platform_name": platform_name,
        'user_email': user_email,
        'confirmation_url': confirmation_url,
        'login_url': login_url,
        'fullname': fullname,
        'helpdesk_url': helpdesk_url
    }
    emails = [user_email]
    html_message = render_to_string('eol_sso_login/emails/verification.txt', context)
    plain_message = strip_tags(html_message)
    from_email = configuration_helpers.get_value(
        'email_from_address',
        settings.BULK_EMAIL_DEFAULT_FROM_EMAIL
    )
    mail = send_mail(
        subject,
        plain_message,
        from_email,
        emails,
        fail_silently=False,
        html_message=html_message)
    return mail
