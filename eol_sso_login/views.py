#!/usr/bin/env python
# -- coding: utf-8 --

import re
import uuid
import json
import logging
import requests
import unidecode
import urllib.parse

from common.djangoapps.student.models import UserProfile
from datetime import datetime
from django.conf import settings
from django_countries import countries
from django.contrib.auth import login, logout
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import User
from django.db import transaction
from django.http import HttpResponseRedirect, HttpResponseForbidden, Http404
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import ugettext as _
from django.views.generic.base import View
from django.http import HttpResponse
from lms.djangoapps.courseware.access import has_access
from lms.djangoapps.courseware.courses import get_course_by_id, get_course_with_access
from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
from openedx.core.djangoapps.user_authn.cookies import set_logged_in_cookies
from opaque_keys.edx.keys import CourseKey
from opaque_keys import InvalidKeyError
from urllib.parse import urlencode

from .models import SSOLoginCuentaUChile, SSOLoginExtraData, SSOLoginCuentaUChileRegistration
from .email_tasks import merge_verification_email, enroll_email
from .utils import validarRut


logger = logging.getLogger(__name__)
regex = r'^(([^ñáéíóú<>()\[\]\.,;:\s@\"]+(\.[^ñáéíóú<>()\[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^ñáéíóú<>()[\]\.,;:\s@\"]+\.)+[^ñáéíóú<>()[\]\.,;:\s@\"]{2,})$'
regex_names = r'^[A-Za-z\s\_]+$'
USERNAME_MAX_LENGTH = 30


class SSOUChile(object):
    def get_user_data(self, dato, is_rut=False):
        """
        Get the user data
        """
        headers = {
            'AppKey': settings.SSOLOGIN_UCHILE_KEY,
            'Origin': settings.LMS_ROOT_URL
        }
        if is_rut:
            params = (('indiv_id', '"{}"'.format(dato)),)
        else:
            params = (('usuario', '"{}"'.format(dato)),)
        base_url = settings.SSOLOGIN_UCHILE_USER_INFO_URL
        result = requests.get(base_url, headers=headers, params=params)

        if result.status_code != 200:
            logger.error(
                "SSOUChile - Api Error: {}, body: {}, dato: {}".format(
                    result.status_code,
                    result.text,
                    dato))
            raise Exception(
                "SSOUChile - Doesnt exists username/rut in PH API, status_code: {}, dato: {}".format(
                    result.status_code, dato))

        data = result.json()
        if data["data"]["getRowsPersona"] is None:
            logger.error(
                "SSOUChile - Doesnt exists username/rut in PH API, status_code: {}, body: {}, dato: {}".format(
                    result.status_code,
                    result.text,
                    dato))
            raise Exception(
                "SSOUChile - Doesnt exists username/rut in PH API, status_code: {}, dato: {}".format(
                    result.status_code, dato))
        if data['data']['getRowsPersona']['status_code'] != 200:
            logger.error(
                "SSOUChile - Api Error: {}, body: {}, dato: {}".format(
                    data['data']['getRowsPersona']['status_code'],
                    result.text,
                    dato))
            raise Exception(
                "SSOUChile - Doesnt exists username/dato in PH API, status_code: {}, dato: {}".format(
                    result.status_code, dato))
        if len(data["data"]["getRowsPersona"]["persona"]) == 0:
            logger.error(
                "SSOUChile - Doesnt exists username/rut in PH API, status_code: {}, body: {}, dato: {}".format(
                    data['data']['getRowsPersona']['status_code'],
                    result.text,
                    dato))
            raise Exception(
                "SSOUChile - Doesnt exists username/rut in PH API, status_code: {}, dato: {}".format(
                    result.status_code, dato))
        if len(data["data"]["getRowsPersona"]["persona"][0]['pasaporte']) == 0:
            logger.error(
                "SSOUChile - Rut doesnt have account in PH API, status_code: {}, body: {}, rut: {}".format(
                    data['data']['getRowsPersona']['status_code'],
                    result.text,
                    rut))
            raise Exception(
                "SSOUChile - Rut doesnt have account in PH API, status_code: {}, rut: {}".format(
                    result.status_code, rut))
        if 'email' not in data["data"]["getRowsPersona"]["persona"][0]:
            logger.error(
                "SSOUChile - Rut doesnt have emails in PH API, status_code: {}, body: {}, rut: {}".format(
                    data['data']['getRowsPersona']['status_code'],
                    result.text,
                    rut))
            raise Exception(
                "SSOUChile - Rut doesnt have emails in PH API, status_code: {}, rut: {}".format(
                    result.status_code, rut))
        elif len(data["data"]["getRowsPersona"]["persona"][0]['email']) == 0:
            logger.error(
                "SSOUChile - Rut doesnt have emails in PH API, status_code: {}, body: {}, rut: {}".format(
                    data['data']['getRowsPersona']['status_code'],
                    result.text,
                    rut))
            raise Exception(
                "SSOUChile - Rut doesnt have emails in PH API, status_code: {}, rut: {}".format(
                    result.status_code, rut))
        if data["data"]["getRowsPersona"]["persona"][0]['pasaporte'][0]['vigencia'] != '1':
            logger.error(
                "SSOUChile - Disabled account in PH API, status_code: {}, body: {}, rut: {}".format(
                    data['data']['getRowsPersona']['status_code'],
                    result.text,
                    rut))
            raise Exception(
                "SSOUChile - Disabled account in PH API, status_code: {}, rut: {}".format(
                    result.status_code, rut))
        getRowsPersona = data["data"]["getRowsPersona"]['persona'][0]
        user_data = {
            'rut': getRowsPersona['indiv_id'],
            'username': data["data"]["getRowsPersona"]["persona"][0]['pasaporte'][0]['usuario'],
            'nombres': getRowsPersona['nombres'],
            'apellidoPaterno': getRowsPersona['paterno'],
            'apellidoMaterno': getRowsPersona['materno'],
            'emails': [email["email"] for email in getRowsPersona["email"]] #to do: check if email list have principal email
        }
        return user_data

    def get_or_create_user(self, user_data):
        """
        Get or create the user given the user data.
        """
        created = False

        with transaction.atomic():
            exists_user = User.objects.filter(email__in=user_data['emails'])
            if exists_user:
                valid_users = []
                is_uchile = None
                for x in exists_user:
                    if not SSOLoginCuentaUChile.objects.filter(user=x).exists() and x.is_active:
                        valid_users.append(x)
                        if '@uchile.cl' in x.email:
                            is_uchile = x
                if is_uchile:
                    user = is_uchile
                elif valid_users:
                    user = valid_users[0]
                else:
                    emails = [x.email for x in exists_user]
                    diff = list(set(user_data['emails']) - set(emails))
                    if diff:
                        user_data['email'] = diff[0]
                        for email in diff:
                            if '@uchile.cl' in email:
                                user_data['email'] = email
                        user = self.create_user_by_data(user_data)
                        created = True
                    else:
                        return None, created
            else:
                user_data['email'] = user_data['emails'][0]
                for email in user_data['emails']:
                    if '@uchile.cl' in email:
                        user_data['email'] = email
                user = self.create_user_by_data(user_data)
                created = True
            return user, created

    def create_user_by_data(self, user_data):
        """
        Create the user by the Django model
        """
        from openedx.core.djangoapps.user_authn.views.registration_form import AccountCreationForm
        from common.djangoapps.student.helpers import do_create_account
        username = self.generate_username(user_data)
        if 'nombreCompleto' not in user_data:
            user_data['nombreCompleto'] = '{} {} {}'.format(user_data['nombres'], user_data['apellidoPaterno'], user_data['apellidoMaterno'])
        if 'pass' in user_data:
            user_pass = user_data['pass']
        else:
            user_pass = BaseUserManager().make_random_password(12)
        form = AccountCreationForm(
            data={
                "username": username,
                "email": user_data['email'],
                "password": user_pass,
                "name": user_data['nombreCompleto'],
            },
            tos_required=False,
            #ignore_email_blacklist=True # only eol/edx-platform have this params
        )
        user, _, reg = do_create_account(form)
        reg.activate()
        reg.save()
        #from common.djangoapps.student.models import create_comments_service_user
        #create_comments_service_user(user)

        return user

    def generate_username(self, user_data):
        """
        Generate an username for the given user_data
        This generation will be done as follow:
        1. return first_name[0] + "_" + last_name[0]
        2. return first_name[0] + "_" + last_name[0] + "_" + last_name[1..N][0..N]
        3. return first_name[0] + "_" first_name[1..N][0..N] + "_" + last_name[0]
        4. return first_name[0] + "_" first_name[1..N][0..N] + "_" + last_name[1..N][0..N]
        5. return first_name[0] + "_" + last_name[0] + N
        """
        if 'nombreCompleto' in user_data:
            aux_username = unidecode.unidecode(user_data['nombreCompleto'].lower())
            aux_username = re.sub(r'[^a-zA-Z0-9\_]', ' ', aux_username)
            aux_username = aux_username.split(" ")
            if len(aux_username) > 1:
                i = int(len(aux_username)/2)
                aux_first_name = aux_username[0:i]
                aux_last_name = aux_username[i:]
            else:
                if User.objects.filter(username=aux_username[0]).exists():
                    for i in range(1, 10000):
                        name_tmp = aux_username[0] + str(i)
                        if not User.objects.filter(username=name_tmp).exists():
                            return name_tmp
                else:
                    return aux_username[0]
        else:
            aux_last_name = ((user_data['apellidoPaterno'] or '') +
                            " " + (user_data['apellidoMaterno'] or '')).strip()
            aux_last_name = unidecode.unidecode(aux_last_name)
            aux_last_name = re.sub(r'[^a-zA-Z0-9\_]', ' ', aux_last_name)
            aux_last_name = aux_last_name.split(" ")
            aux_first_name = unidecode.unidecode(user_data['nombres'])
            aux_first_name = re.sub(r'[^a-zA-Z0-9\_]', ' ', aux_first_name)
            aux_first_name = aux_first_name.split(" ")

        first_name = [x for x in aux_first_name if x != ''] or ['']
        last_name = [x for x in aux_last_name if x != ''] or ['']

        # 1.
        test_name = first_name[0] + "_" + last_name[0]
        if len(test_name) <= USERNAME_MAX_LENGTH and not User.objects.filter(
                username=test_name).exists():
            return test_name

        # 2.
        for i in range(len(last_name[1:])):
            test_name = test_name + "_"
            for j in range(len(last_name[i + 1])):
                test_name = test_name + last_name[i + 1][j]
                if len(test_name) > USERNAME_MAX_LENGTH:
                    break
                if not User.objects.filter(username=test_name).exists():
                    return test_name

        # 3.
        first_name_temp = first_name[0]
        for i in range(len(first_name[1:])):
            first_name_temp = first_name_temp + "_"
            for j in range(len(first_name[i + 1])):
                first_name_temp = first_name_temp + first_name[i + 1][j]
                test_name = first_name_temp + "_" + last_name[0]
                if len(test_name) > USERNAME_MAX_LENGTH:
                    break
                if not User.objects.filter(username=test_name).exists():
                    return test_name

        # 4.
        first_name_temp = first_name[0]
        for first_index in range(len(first_name[1:])):
            first_name_temp = first_name_temp + "_"
            for first_second_index in range(len(first_name[first_index + 1])):
                first_name_temp = first_name_temp + \
                    first_name[first_index + 1][first_second_index]
                test_name = first_name_temp + "_" + last_name[0]
                if len(test_name) > USERNAME_MAX_LENGTH:
                    break
                for second_index in range(len(last_name[1:])):
                    test_name = test_name + "_"
                    for second_second_index in range(
                            len(last_name[second_index + 1])):
                        test_name = test_name + \
                            last_name[second_index + 1][second_second_index]
                        if len(test_name) > USERNAME_MAX_LENGTH:
                            break
                        if not User.objects.filter(
                                username=test_name).exists():
                            return test_name

        # 5.
        # Make sure we have space to add the numbers in the username
        test_name = first_name[0] + "_" + last_name[0]
        test_name = test_name[0:(USERNAME_MAX_LENGTH - 5)]
        if test_name[-1] == '_':
            test_name = test_name[:-1]
        for i in range(1, 10000):
            name_tmp = test_name + str(i)
            if not User.objects.filter(username=name_tmp).exists():
                return name_tmp

        # Username cant be generated
        raise Exception("Error generating username for name {}".format())

class SSOLoginUChileRedirect(View):
    def get(self, request):
        redirect_url = request.GET.get('next', "/")
        if request.user.is_authenticated:
            return HttpResponseRedirect(redirect_url)

        return HttpResponseRedirect(
            '{}?{}'.format(
                settings.SSOLOGIN_UCHILE_REQUEST_URL,
                urlencode(
                    self.service_parameters(request))))

    def service_parameters(self, request):
        """
        store the service parameter for eol_sso_login.
        """

        parameters = {
            'service': SSOLoginUChileRedirect.get_callback_url(request),
            'renew': 'true'
        }
        return parameters

    @staticmethod
    def get_callback_url(request):
        """
        Get the callback url
        """
        import base64
        redirect_url = base64.b64encode(request.GET.get('next', "/").encode("utf-8")).decode("utf-8")
        url = request.build_absolute_uri(
            reverse('eol_sso_login:uchile_callback'))
        return '{}?next={}'.format(url, redirect_url)

class SSOLoginUChileVerification(View):
    def get(self, request):
        logout(request)
        verification_id = request.GET.get('id', "")
        if verification_id == '':
            logger.info('EdxLoginVerification - Error, empty ID')
            raise Http404()
        if SSOLoginCuentaUChileRegistration.objects.filter(activation_key=verification_id).exists():
            ssologin_register = SSOLoginCuentaUChileRegistration.objects.get(activation_key=verification_id)
            ssologin_register.activation_timestamp = datetime.utcnow()
            ssologin_register.save()
            try:
                ssologin_user = SSOLoginCuentaUChile.objects.get(user=ssologin_register.user)
                ssologin_user.is_active = True
                ssologin_user.save()
                return render(request, 'eol_sso_login/verification.html', {'action': 'verification', 'result': 'success'})
            except SSOLoginCuentaUChile.DoesNotExist:
                logger.info('EdxLoginVerification - Error to get SSOLoginCuentaUChile, user: {}'.format(ssologin_register.user))
                return render(request, 'eol_sso_login/verification.html', {'action': 'verification', 'result': 'error'})
        logger.info('EdxLoginVerification - Verification Id does not exists, id: {}'.format(verification_id))
        raise Http404()
                
class SSOLoginUChileVerificationData(View):
    def get(self, request):
        if not request.user.is_authenticated:
            return HttpResponseRedirect('/')
        context = {
            'action': 'data',
        }
        context['sttgs_data'] = self.get_profile_settings()
        context['user_data'] = self.get_user_extra_data(request.user)
        return render(request, 'eol_sso_login//verification.html', context)

    def post(self, request):
        if not request.user.is_authenticated:
            raise Http404()
        context = {
            'action': 'data',
            'result': ''
        }
        profile_sttgs = self.get_profile_settings()
        if self.data_valid(request.POST, profile_sttgs, request.user):
            self.update_user(request.user, request.POST)
            context['result'] = 'success'
        else:
            context['result'] = 'error'
        context['sttgs_data'] = profile_sttgs
        context['user_data'] = self.get_user_extra_data(request.user)
        return render(request, 'eol_sso_login//verification.html', context)
    
    def update_user(self, user, data):
        user.profile.year_of_birth = int(data['year_of_birth'])
        user.profile.gender = data['gender']
        user.profile.level_of_education = data['level_of_education']
        user.profile.country = data['country']
        user.profile.save()
        document = data['document'].upper().strip()
        if data['type_document'] == 'rut':
            document = document.replace("-", "")
            document = document.replace(".", "")
            while len(document) < 10:
                document = "0" + document
        try:
            ssologin_data = SSOLoginExtraData.objects.get(user=user)
            ssologin_data.document = document
            ssologin_data.type_document = data['type_document']
            ssologin_data.is_completed = True
            ssologin_data.save()
        except SSOLoginExtraData.DoesNotExist:
            try:
                with transaction.atomic():
                    SSOLoginExtraData.objects.create(
                        user = user,
                        document = document,
                        type_document = data['type_document'],
                        is_completed = True
                        )
            except Exception as e:
                logger.error("SSOLoginVerificationData - Error update SSOLoginExtraData, user: {}, data: {}, error: {}".format(user, data, str(e)))
                pass

    def data_valid(self, data, profile_sttgs, user):
        keys = ["country", "level_of_education", "gender", "year_of_birth", "document", "type_document"]
        if not all(k in data for k in keys):
            logger.info('SSOLoginVerificationData - Missing params, user: {}, POST: {}'.format(user, data))
            return False
        #dict
        if data['country'] not in profile_sttgs['countries']:
            logger.info('SSOLoginVerificationData - Wrong Country, user: {}, POST: {}'.format(user, data))
            return False
        #tuple
        if not (any(data['gender'] in i for i in profile_sttgs['gender'])):
            logger.info('SSOLoginVerificationData - Wrong Gender, user: {}, POST: {}'.format(user, data))
            return False
        #tuple
        if not (any(data['level_of_education'] in i for i in profile_sttgs['level_of_education'])):
            logger.info('SSOLoginVerificationData - Wrong level education, user: {}, POST: {}'.format(user, data))
            return False
        #array
        try:
            if int(data['year_of_birth']) not in profile_sttgs['year']:
                logger.info('SSOLoginVerificationData - Wrong Year, user: {}, POST: {}'.format(user, data))
                return False
        except ValueError:
            logger.info('SSOLoginVerificationData - Year is not a number, user: {}, POST: {}'.format(user, data))
            return False
        #tuple
        if not (any(data['type_document'] in i for i in profile_sttgs['type_document'])):
            logger.info('SSOLoginVerificationData - Wrong type_document, user: {}, POST: {}'.format(user, data))
            return False
        #string
        document = data['document']
        type_document = data['type_document']
        if len(document) == 0:
            logger.info('SSOLoginVerificationData - document length is zero, user: {}, POST: {}'.format(user, data))
            return False
        if 5 > len(document) or len(document) > 20:
            logger.info('SSOLoginVerificationData - Wrong document length, user: {}, POST: {}'.format(user, data))
            return False
        if type_document != 'rut' and not document.isalnum():
            logger.info('SSOLoginVerificationData - Wrong document, it doesnt alpha numeric, user: {}, POST: {}'.format(user, data))
            return False
        try:
            if type_document == 'rut' and not validarRut(document):
                logger.info('SSOLoginVerificationData - Wrong document when is Rut, user: {}, POST: {}'.format(user, data))
                return False
        except ValueError:
            logger.info('SSOLoginVerificationData - Wrong document when is Rut, user: {}, POST: {}'.format(user, data))
            return False

        if type_document == 'rut':
            document = document.replace("-", "")
            document = document.replace(".", "")
            while len(document) < 10:
                document = "0" + document

        if not SSOLoginExtraData.objects.filter(document=document, type_document=type_document, user=user).exists():
            if SSOLoginExtraData.objects.filter(document=document, type_document=type_document).exists():
                logger.info('SSOLoginVerificationData - document with type document already exists, user: {}, POST: {}'.format(user, data))
                return False
        return True

    def get_profile_settings(self):
        data = {
            'countries': countries.countries,
            'gender': UserProfile().GENDER_CHOICES,
            'level_of_education': UserProfile().LEVEL_OF_EDUCATION_CHOICES,
            'year': UserProfile().VALID_YEARS,
            'type_document': SSOLoginExtraData().MODE_CHOICES,
        }
        return data

    def get_user_extra_data(self, user):
        data = {
            'document': '',
            'type_document': '',
            'country': user.profile.country,
            'gender': user.profile.gender,
            'level_of_education': user.profile.level_of_education,
            'year': user.profile.year_of_birth,
        }
        try:
            ssologin_data = SSOLoginExtraData.objects.get(user=user)
            data['document'] = ssologin_data.document
            data['type_document'] = ssologin_data.type_document
        except SSOLoginExtraData.DoesNotExist:
            pass
        return data

class SSOLoginUChileVerificationPending(View):
    def get(self, request):
        mail = request.GET.get('mail','')
        context = {
            'action': 'pending',
            'mail': mail
        }
        return render(request, 'eol_sso_login//verification.html', context)

class SSOLoginUChileCallback(View, SSOUChile):

    def get(self, request):
        import base64
        from openedx.core.djangoapps.user_authn.utils import is_safe_login_or_logout_redirect

        ticket = request.GET.get('ticket')
        redirect_url = base64.b64decode(
            request.GET.get(
                'next', "Lw==")).decode('utf-8')
        if not is_safe_login_or_logout_redirect(redirect_url, request.get_host(), None, False):
            redirect_url = "/"
        error_url = reverse('eol_sso_login:uchile_login')

        if ticket is None:
            logger.exception("SSOLoginUChileCallback - ticket is None")
            return HttpResponseRedirect(
                '{}?next={}'.format(
                    error_url, redirect_url))

        username = self.verify_state(request, ticket)
        if username is None:
            logger.exception("SSOLoginUChileCallback - username is None")
            return HttpResponseRedirect(
                '{}?next={}'.format(
                    error_url, redirect_url))
        try:
            return self.create_login_user(request, username, error_url, redirect_url)
        except Exception as e:
            logger.exception("SSOLoginUChileCallback - Error logging {} - {}, error: {}".format(username, ticket, str(e)))
            return HttpResponseRedirect(
                '{}?next={}'.format(
                    error_url, redirect_url))

    def verify_state(self, request, ticket):
        """
            Verify if the ticket is correct
        """
        url = request.build_absolute_uri(
            reverse('eol_sso_login:uchile_callback'))
        parameters = {
            'service': '{}?next={}'.format(
                url,
                request.GET.get('next')),
            'ticket': ticket,
            'renew': 'true'}
        result = requests.get(
            settings.SSOLOGIN_UCHILE_RESULT_VALIDATE,
            params=urlencode(parameters),
            headers={
                'content-type': 'application/x-www-form-urlencoded',
                'User-Agent': 'curl/7.58.0'})
        if result.status_code == 200:
            r = result.content.decode('utf-8').split('\n')
            if r[0] == 'yes':
                return r[1]

        return None

    def create_login_user(self, request, username, error_url, redirect_url):
        """
        Get or create the user and log him in.
        """
        platform_name = configuration_helpers.get_value('PLATFORM_NAME', settings.PLATFORM_NAME)
        login_url = request.build_absolute_uri('/login')
        helpdesk_url = request.build_absolute_uri('/contact_form')
        user_data = self.get_user_data(username)
        try:
            ssologin_user = SSOLoginCuentaUChile.objects.get(username=user_data['username'])
            if ssologin_user.is_active:
                if request.user.is_anonymous or request.user.id != ssologin_user.user.id:
                    logout(request)
                    login(
                        request,
                        ssologin_user.user,
                        backend="django.contrib.auth.backends.AllowAllUsersModelBackend",
                    )
                    ssologin_user.login_timestamp = datetime.utcnow()
                    ssologin_user.save()
                if SSOLoginExtraData.objects.filter(user=ssologin_user.user, is_completed=True).exists():
                    response = HttpResponseRedirect(redirect_url)
                else:
                    response = HttpResponseRedirect(reverse('eol_sso_login:verification-data'))
                response = set_logged_in_cookies(request, response, ssologin_user.user)
                return response
            else:
                try:
                    ssologin_register = SSOLoginCuentaUChileRegistration.objects.get(user=ssologin_user.user)
                except SSOLoginCuentaUChileRegistration.DoesNotExist:
                    ssologin_register = SSOLoginCuentaUChileRegistration.objects.create(
                        username=user_data['username'],
                        user=ssologin_user.user,
                        activation_key=uuid.uuid4().hex
                    )
                confirmation_url = request.build_absolute_uri('{}?{}'.format(reverse('eol_sso_login:verification'), urlencode({'id':ssologin_register.activation_key})))
                merge_verification_email.delay(ssologin_user.user.profile.name, ssologin_user.user.email, confirmation_url, login_url, helpdesk_url, platform_name)
                aux_url = '{}?{}'.format( reverse('eol_sso_login:verification-pending'), urlencode({'mail':ssologin_user.user.email}))
                return HttpResponseRedirect(aux_url)
        except SSOLoginCuentaUChile.DoesNotExist:
            user, created = self.get_or_create_user(user_data)
            if user is None:
                logger.error("SSOLoginUChileCallback - Error to get or create user, user_data: {}".format(user_data))
                return HttpResponseRedirect('{}?next={}'.format(error_url, redirect_url))
            if created:
                ssologin_user = SSOLoginCuentaUChile.objects.create(
                    user=user,
                    username=user_data['username'],
                    is_active=True,
                    login_timestamp=datetime.utcnow()
                )
                response = HttpResponseRedirect(reverse('eol_sso_login:verification-data'))
                if request.user.is_anonymous or request.user.id != ssologin_user.user.id:
                    logout(request)
                    login(
                        request,
                        ssologin_user.user,
                        backend="django.contrib.auth.backends.AllowAllUsersModelBackend",
                    )
                    response = set_logged_in_cookies(request, response, user)
                return response
            else:
                try:
                    ssologin_register = SSOLoginCuentaUChileRegistration.objects.get(user=user)
                except SSOLoginCuentaUChileRegistration.DoesNotExist:
                    ssologin_register = SSOLoginCuentaUChileRegistration.objects.create(
                        username=user_data['username'],
                        user=user,
                        activation_key=uuid.uuid4().hex
                    )
                fullname = '{} {} {}'.format(user_data['nombres'], user_data['apellidoPaterno'], user_data['apellidoMaterno'])
                confirmation_url = request.build_absolute_uri('{}?{}'.format(reverse('eol_sso_login:verification'), urlencode({'id':ssologin_register.activation_key})))
                merge_verification_email.delay(fullname, user.email, confirmation_url, login_url, helpdesk_url, platform_name)
                ssologin_user = SSOLoginCuentaUChile.objects.create(
                    user=user,
                    username=user_data['username'],
                    is_active=False
                )
                aux_url = '{}?{}'.format(reverse('eol_sso_login:verification-pending'), urlencode({'mail':user.email}))
                return HttpResponseRedirect(aux_url)

class SSOEnroll(View, SSOUChile):
    def get(self, request):
        if not request.user.is_anonymous:
            if request.user.is_staff:
                context = {
                    'datos': '', 
                    'auto_enroll': True, 
                    'modo': 'honor', 
                    'send_email': True, 
                    'curso': '',
                    'document_type': 'rut'
                    }
                return render(request, 'eol_sso_login/external.html', context)
            else:
                logger.error("SSOEnroll - User is not staff, user: {}".format(request.user))
        else:
            logger.error("SSOEnroll - User is Anonymous")
        raise Http404()
    
    def post(self, request):
        if not request.user.is_anonymous:
            if request.user.is_staff:
                lista_data = []
                aux_datos = request.POST.get("datos", "").lower().split('\n')
                # limpieza de los datos ingresados
                for x in aux_datos:
                    x = x.strip()
                    if x:
                        lista_data.append([y.strip() for y in x.split(",")])
                # verifica si el checkbox de auto enroll fue seleccionado
                enroll = False
                if request.POST.getlist("enroll"):
                    enroll = True
                # verifica si el checkbox de send_email fue seleccionado
                send_email = False
                if request.POST.getlist("send_email"):
                    send_email = True
                context = {
                    'datos': request.POST.get("datos", ""),
                    'curso': request.POST.get("course", ""),
                    'document_type': request.POST.get("document_type", None),
                    'auto_enroll': enroll,
                    'send_email': send_email,
                    'modo': request.POST.get("modes", None)}
                # validacion de datos
                context = self.validate_data(request.user, lista_data, context)
                # retorna si hubo al menos un error
                if len(context) > 6:
                    return render(request, 'eol_sso_login/external.html', context)
                course_id = context['curso'].strip()
                lista_saved, lista_not_saved = self.enroll_create_user(
                    course_id, context['modo'], lista_data, enroll, request.POST.get("document_type"))
                login_url = request.build_absolute_uri('/login')
                helpdesk_url = request.build_absolute_uri('/contact_form')
                confirmation_url = request.build_absolute_uri(reverse('eol_sso_login:verification'))
                course = get_course_by_id(CourseKey.from_string(course_id))
                course_name =  course.display_name_with_default
                email_saved = []
                for d in lista_saved:
                    if send_email:
                        enroll_email.delay(d, course_name, login_url, helpdesk_url, confirmation_url)
                    aux = d
                    aux.pop('password', None)
                    email_saved.append(aux)
                context = {
                    'datos': '',
                    'auto_enroll': True,
                    'send_email': True,
                    'curso': '',
                    'modo': 'honor',
                    'document_type': 'rut',
                    'action_send': send_email
                }
                if len(email_saved) > 0:
                    context['lista_saved'] = email_saved
                if len(lista_not_saved) > 0:
                    context['lista_not_saved'] = lista_not_saved
                return render(request, 'eol_sso_login/external.html', context)
            else:
                logger.error("SSOEnroll - User dont have permission or is not staff, user: {}".format(request.user))
                raise Http404()
        else:
            logger.error("SSOEnroll - User is Anonymous")
            raise Http404()
    
    def validate_data(self, user, lista_data, context):
        wrong_data = []
        duplicate_data = [[],[]]
        original_data = [[],[]]
        # si no se ingreso datos
        if not lista_data:
            logger.error("SSOEnroll - Empty Data, user: {}".format(user.id))
            context['no_data'] = ''
        if len(lista_data) > 50:
            logger.error("SSOEnroll - data limit is 50, length data: {} user: {}".format(len(lista_data),user.id))
            context['limit_data'] = ''
        else:
            for data in lista_data:
                data = [d.strip() for d in data]
                if len(data) == 1 or len(data) > 3:
                    wrong_data.append(data)
                else:
                    if len(data) == 2:
                        data.append("")
                    if data[0] != "" and data[1] != "":
                        aux_name = unidecode.unidecode(data[0])
                        aux_name = re.sub(r'[^a-zA-Z0-9\_]', ' ', aux_name)
                        if not re.match(regex_names, aux_name):
                            logger.error("SSOEnroll - Wrong Name, not allowed specials characters, {}".format(data))
                            wrong_data.append(data)
                        elif not re.match(regex, data[1]):
                            logger.error("SSOEnroll - Wrong Email {}, data: {}".format(data[1], data))
                            wrong_data.append(data)
                        elif data[2] != "" and context['document_type'] == 'rut' and not validarRut(data[2]):
                            logger.error("SSOEnroll - Wrong Document {}, data: {}".format(data[2], data))
                            wrong_data.append(data)
                        elif data[1] in original_data[0] or (data[2] != '' and data[2] in original_data[1]):
                            if data[1] in original_data[0]:
                                duplicate_data[0].append(data[1])
                            if data[2] != '' and data[2] in original_data[1]:
                                duplicate_data[1].append(data[2])
                        else:
                            original_data[0].append(data[1])
                            if data[2] != '':
                                original_data[1].append(data[2])
                    else:
                        wrong_data.append(data)
        if len(wrong_data) > 0:
            context['wrong_data'] = wrong_data
        if len(duplicate_data[0]) > 0:
            context['duplicate_email'] = duplicate_data[0]
        if len(duplicate_data[1]) > 0:
            context['duplicate_rut'] = duplicate_data[1]
        # si el modo es incorrecto
        if not context['modo'] in ['honor', 'verified', 'audit']:
            context['error_mode'] = ''
        # si el document_type es incorrecto
        if not context['document_type'] in ['rut', 'passport', 'dni']:
            context['error_document_type'] = ''
        # valida curso
        if context['curso'] == "":
            logger.error("SSOEnroll - Empty course, user: {}".format(user.id))
            context['curso2'] = ''
        # valida si existe el curso
        else:
            course_id = context['curso'].strip()
            
            if not self.validate_course(course_id):
                context['error_curso'] = True
                logger.error("SSOEnroll - Course dont exists, user: {}, course_id: {}".format(user.id, course_id))
            if 'error_curso' not in context:
                if not self.validate_user(user, course_id):
                    context['error_permission'] = True
                    logger.error("SSOEnroll - User dont have permission, user: {}, course_id: {}".format(user.id, course_id))
        return context
    
    def validate_course(self, course_id):
        """
            Verify if course.id exists
        """
        from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
        try:
            aux = CourseKey.from_string(course_id)
            return CourseOverview.objects.filter(id=aux).exists()
        except InvalidKeyError:
            return False

    def is_course_staff(self, user, course_id):
        """
            Verify if the user is staff course
        """
        try:
            course_key = CourseKey.from_string(course_id)
            course = get_course_with_access(user, "load", course_key)

            return bool(has_access(user, 'staff', course))
        except Exception:
            return False

    def is_instructor(self, user, course_id):
        """
            Verify if the user is instructor
        """
        try:
            course_key = CourseKey.from_string(course_id)
            course = get_course_with_access(user, "load", course_key)
            return bool(has_access(user, 'instructor', course))
        except Exception:
            return False

    def validate_user(self, user, course_id):
        """
            Verify if the user have permission
        """
        access = False
        if not user.is_anonymous:
            if user.is_staff:
                access = True
            if self.is_instructor(user, course_id):
                access = True
            if self.is_course_staff(user, course_id):
                access = True
        return access

    def enroll_create_user(self, course_id, mode, lista_data, enroll, document_type):
        lista_saved = []
        lista_not_saved = []
        for dato in lista_data:
            if len(dato) == 2:
                dato.append("")
            if document_type == 'rut':
                dato[2] = dato[2].upper()
                dato[2] = dato[2].replace("-", "")
                dato[2] = dato[2].replace(".", "")
                while len(dato[2]) > 0 and len(dato[2]) < 10:
                    dato[2] = "0" + dato[2]
            aux_pass = BaseUserManager().make_random_password(12)
            aux_pass = aux_pass.lower()
            with transaction.atomic():
                user, created = self.get_or_create_user_with_run(dato, aux_pass, document_type)
            if user is None:
                lista_not_saved.append(dato)
            else:
                if dato[2] != '' and not SSOLoginExtraData.objects.filter(user=user).exists():
                    try:
                        with transaction.atomic():
                            SSOLoginExtraData.objects.create(
                                user=user,
                                document=dato[2],
                                type_document=document_type
                            )
                    except Exception as e:
                        logger.error("SSOEnroll - Error to create SSOLoginExtraData, user:{}, data: {}, error: {}".format(user, dato, str(e)))
                        pass
                self.enroll_course_user(user, course_id, enroll, mode)
                have_sso = SSOLoginCuentaUChile.objects.filter(user=user).exists()
                active_sso = SSOLoginCuentaUChile.objects.filter(user=user, is_active=True).exists()
                activation_key = ''
                if not active_sso:
                    try:
                        ssologin_register = SSOLoginCuentaUChileRegistration.objects.get(user=user)
                        activation_key = ssologin_register.activation_key
                    except Exception:
                        pass
                lista_saved.append({
                    'email': dato[1],
                    'document': dato[2],
                    'password': aux_pass,
                    'username': user.username,
                    'created': created,
                    'email2': user.email,
                    'have_sso': have_sso,
                    'active_sso': active_sso,
                    'fullname': user.profile.name.strip(),
                    'activation_key': activation_key
                })
        return lista_saved, lista_not_saved

    def enroll_course_user(self, user, course_id, enroll, mode):
        from common.djangoapps.student.models import CourseEnrollment, CourseEnrollmentAllowed
        if enroll:
            CourseEnrollment.enroll(
                user,
                CourseKey.from_string(course_id),
                mode=mode)
        else:
            CourseEnrollmentAllowed.objects.create(
                course_id=CourseKey.from_string(course_id),
                email=user.email,
                user=user)

    def get_or_create_user_with_run(self, dato, password, document_type):
        if User.objects.filter(email=dato[1]).exists():
            return User.objects.get(email=dato[1]), False
        else:
            if SSOLoginExtraData.objects.filter(document=dato[2], type_document=document_type).exists():
                ssologin_data = SSOLoginExtraData.objects.get(document=dato[2], type_document=document_type)
                return ssologin_data.user, False
            else:
                if document_type == 'rut' and dato[2] != "":
                    user, created = self.get_user(dato, password)
                else:
                    user, created = self.create_user(dato, password)
                return user, created

    def get_user(self, dato, password):
        try:
            user_data = self.get_user_data(dato[2], is_rut=True)
            try:
                ssologin_user = SSOLoginCuentaUChile.objects.get(username=user_data['username'])
                return ssologin_user.user, False
            except SSOLoginCuentaUChile.DoesNotExist:
                user_data['pass'] = password
                user, created = self.get_or_create_user(user_data)
                if user is None:
                    return None, False
                if created:
                    ssologin_user = SSOLoginCuentaUChile.objects.create(
                        user=user,
                        username=user_data['username'],
                        is_active=True
                    )
                else:
                    try:
                        ssologin_register = SSOLoginCuentaUChileRegistration.objects.get(user=user)
                    except SSOLoginCuentaUChileRegistration.DoesNotExist:
                        ssologin_register = SSOLoginCuentaUChileRegistration.objects.create(
                            username=user_data['username'],
                            user=user,
                            activation_key=uuid.uuid4().hex
                        )
                    ssologin_user = SSOLoginCuentaUChile.objects.create(
                        user=user,
                        username=user_data['username'],
                        is_active=False
                    )
                return user, created
        except Exception as e:
            logger.error("SSOEnroll - Error to get/create user with api ph, dato: {}, error: {}".format(dato, str(e)))
            return self.create_user(dato, password)

    def create_user(self, dato, password):
        user_data = {
            'nombreCompleto': dato[0],
            'pass': password,
            'email': dato[1]
        }
        try:
            user = self.create_user_by_data(user_data)
            return user, True
        except Exception as e:
            logger.error('SSOEnroll - Error to create_user_by_data, data: {}, error: {}'.format(dato, str(e)))
            return None, False

