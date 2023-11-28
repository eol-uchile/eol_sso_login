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
from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
from urllib.parse import urlencode

from .models import SSOLoginCuentaUChile, SSOLoginExtraData, SSOLoginCuentaUChileRegistration
from .email_tasks import merge_verification_email
from .utils import validarRut


logger = logging.getLogger(__name__)
regex = r'^(([^ñáéíóú<>()\[\]\.,;:\s@\"]+(\.[^ñáéíóú<>()\[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^ñáéíóú<>()[\]\.,;:\s@\"]+\.)+[^ñáéíóú<>()[\]\.,;:\s@\"]{2,})$'
regex_names = r'^[A-Za-z\s\_]+$'
USERNAME_MAX_LENGTH = 30


class SSOUChile(object):
    def get_user_data(self, username):
        """
        Get the user data
        """
        headers = {
            'AppKey': settings.SSOLOGIN_UCHILE_KEY,
            'Origin': settings.LMS_ROOT_URL
        }
        params = (('usuario', '"{}"'.format(username)),)
        base_url = settings.SSOLOGIN_UCHILE_USER_INFO_URL
        result = requests.get(base_url, headers=headers, params=params)

        if result.status_code != 200:
            logger.error(
                "SSOUChile - Api Error: {}, body: {}, username: {}".format(
                    result.status_code,
                    result.text,
                    username))
            raise Exception(
                "SSOUChile - Doesnt exists username in PH API, status_code: {}, username: {}".format(
                    result.status_code, username))

        data = json.loads(result.text)
        if data["data"]["getRowsPersona"] is None:
            logger.error(
                "SSOUChile - Doesnt exists rut in PH API, status_code: {}, body: {}, username: {}".format(
                    result.status_code,
                    result.text,
                    username))
            raise Exception(
                "SSOUChile - Doesnt exists username in PH API, status_code: {}, username: {}".format(
                    result.status_code, username))
        if data['data']['getRowsPersona']['status_code'] != 200:
            logger.error(
                "SSOUChile - Api Error: {}, body: {}, username: {}".format(
                    data['data']['getRowsPersona']['status_code'],
                    result.text,
                    username))
            raise Exception(
                "SSOUChile - Doesnt exists username in PH API, status_code: {}, username: {}".format(
                    result.status_code, username))
        if len(data["data"]["getRowsPersona"]["persona"]) == 0:
            logger.error(
                "SSOUChile - Doesnt exists rut in PH API, status_code: {}, body: {}, username: {}".format(
                    data['data']['getRowsPersona']['status_code'],
                    result.text,
                    username))
            raise Exception(
                "SSOUChile - Doesnt exists username in PH API, status_code: {}, username: {}".format(
                    result.status_code, username))
        if len(data["data"]["getRowsPersona"]["persona"][0]['pasaporte']) == 0:
            logger.error(
                "SSOUChile - Doesnt exists rut in PH API, status_code: {}, body: {}, rut: {}".format(
                    data['data']['getRowsPersona']['status_code'],
                    result.text,
                    rut))
            raise Exception(
                "SSOUChile - Doesnt exists rut in PH API, status_code: {}, rut: {}".format(
                    result.status_code, rut))
        getRowsPersona = data["data"]["getRowsPersona"]['persona'][0]
        user_data = {
            'rut': getRowsPersona['indiv_id'],
            'username': username,
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
                        user = self.create_user_by_data(user_data, False)
                        created = True
                    else:
                        return None, created
            else:
                user_data['email'] = user_data['emails'][0]
                for email in user_data['emails']:
                    if '@uchile.cl' in email:
                        user_data['email'] = email
                user = self.create_user_by_data(user_data, False)
                created = True
        return user, created

    def create_user_by_data(self, user_data, have_pass):
        """
        Create the user by the Django model
        """
        from openedx.core.djangoapps.user_authn.views.registration_form import AccountCreationForm
        from common.djangoapps.student.helpers import do_create_account
        username = self.generate_username(user_data)
        if 'nombreCompleto' not in user_data:
            user_data['nombreCompleto'] = '{} {} {}'.format(user_data['nombres'], user_data['apellidoPaterno'], user_data['apellidoMaterno'])
        if have_pass:
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
            #ignore_email_blacklist=True # only eol-edx-platform have this params
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
            while len(document) < 10:
                document = "0" + document
        try:
            ssologin_data = SSOLoginExtraData.objects.get(user=user)
        except SSOLoginExtraData.DoesNotExist:
            ssologin_data = SSOLoginExtraData.objects.create(user=user)
        ssologin_data.document = document
        ssologin_data.type_document = data['type_document']
        ssologin_data.save()

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
            is_logged = self.create_login_user(request, username)
            if is_logged is False:
                return HttpResponseRedirect('{}?next={}'.format(error_url, redirect_url))
            elif is_logged is True:
                return HttpResponseRedirect(redirect_url)
            else:
                return HttpResponseRedirect(is_logged)
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

    def create_login_user(self, request, username):
        """
        Get or create the user and log him in.
        """
        platform_name = configuration_helpers.get_value('PLATFORM_NAME', settings.PLATFORM_NAME)
        login_url = request.build_absolute_uri('/login')
        helpdesk_url = request.build_absolute_uri('/contact_form')
        try:
            ssologin_user = SSOLoginCuentaUChile.objects.get(username=username)
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
                if SSOLoginExtraData.objects.filter(user=ssologin_user.user).exists():
                    return True
                else:
                    return reverse('eol_sso_login:verification-data')
            else:
                try:
                    ssologin_register = SSOLoginCuentaUChileRegistration.objects.get(user=ssologin_user.user)
                except SSOLoginCuentaUChileRegistration.DoesNotExist:
                    ssologin_register = SSOLoginCuentaUChileRegistration.objects.create(
                        user=ssologin_user.user,
                        activation_key=uuid.uuid4().hex
                    )
                confirmation_url = request.build_absolute_uri('{}?{}'.format(reverse('eol_sso_login:verification'), urlencode({'id':ssologin_register.activation_key})))
                merge_verification_email.delay(ssologin_user.user.profile.name, ssologin_user.user.email, confirmation_url, login_url, helpdesk_url, platform_name)
                return '{}?{}'.format( reverse('eol_sso_login:verification-pending'), urlencode({'mail':ssologin_user.user.email}))
        except SSOLoginCuentaUChile.DoesNotExist:
            user_data = self.get_user_data(username)
            user, created = self.get_or_create_user(user_data)
            if user is None:
                logger.error("SSOLoginUChileCallback - Error to get or create user, user_data: {}".format(user_data))
                return False
            if created:
                ssologin_user = SSOLoginCuentaUChile.objects.create(
                    user=user,
                    username=username,
                    is_active=True,
                    login_timestamp=datetime.utcnow()
                )
                if request.user.is_anonymous or request.user.id != ssologin_user.user.id:
                    logout(request)
                    login(
                        request,
                        ssologin_user.user,
                        backend="django.contrib.auth.backends.AllowAllUsersModelBackend",
                    )
                return reverse('eol_sso_login:verification-data')
            else:
                try:
                    ssologin_register = SSOLoginCuentaUChileRegistration.objects.get(user=user)
                except SSOLoginCuentaUChileRegistration.DoesNotExist:
                    ssologin_register = SSOLoginCuentaUChileRegistration.objects.create(
                        user=user,
                        activation_key=uuid.uuid4().hex
                    )
                fullname = '{} {} {}'.format(user_data['nombres'], user_data['apellidoPaterno'], user_data['apellidoMaterno'])
                confirmation_url = request.build_absolute_uri('{}?{}'.format(reverse('eol_sso_login:verification'), urlencode({'id':ssologin_register.activation_key})))
                merge_verification_email.delay(fullname, user.email, confirmation_url, login_url, helpdesk_url, platform_name)
                ssologin_user = SSOLoginCuentaUChile.objects.create(
                    user=user,
                    username=username,
                    is_active=False
                )
                return '{}?{}'.format(reverse('eol_sso_login:verification-pending'), urlencode({'mail':user.email}))

