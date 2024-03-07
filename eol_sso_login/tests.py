#!/usr/bin/env python
# -*- coding: utf-8 -*-
from mock import patch, Mock, MagicMock
from collections import namedtuple
from django.urls import reverse
from django.test import TestCase, Client
from django.test import Client
from django.conf import settings
from django.contrib.auth.models import Permission, User
from django.contrib.contenttypes.models import ContentType
from urllib.parse import parse_qs
from opaque_keys.edx.locator import CourseLocator
from xmodule.modulestore.tests.factories import CourseFactory, ItemFactory
from xmodule.modulestore import ModuleStoreEnum
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
from common.djangoapps.student.tests.factories import CourseEnrollmentAllowedFactory, UserFactory, CourseEnrollmentFactory
from common.djangoapps.student.roles import CourseInstructorRole, CourseStaffRole
import re
import json
import urllib.parse
import uuid
from .views import SSOUChile, SSOLoginUChileVerificationData
from .models import SSOLoginCuentaUChile, SSOLoginExtraData, SSOLoginCuentaUChileRegistration
from .utils import validarRut


class TestSSOLoginUChileRedirect(TestCase):

    def setUp(self):
        self.client = Client()

    def test_set_session(self):
        result = self.client.get(reverse('eol_sso_login:uchile_login'))
        self.assertEqual(result.status_code, 302)

    def test_return_request(self):
        """
            Test if return request is correct
        """
        result = self.client.get(reverse('eol_sso_login:uchile_login'))
        request = urllib.parse.urlparse(result.url)
        args = urllib.parse.parse_qs(request.query)

        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.netloc, '172.25.14.193:9513')
        self.assertEqual(request.path, '/login')
        self.assertEqual(
            args['service'][0],
            "http://testserver/eol_sso_login/uchile_callback/?next=Lw==")

    def test_redirect_already_logged(self):
        """
            Test redirect when the user is already logged
        """
        user = User.objects.create_user(username='testuser', password='123')
        self.client.login(username='testuser', password='123')
        result = self.client.get(reverse('eol_sso_login:uchile_login'))
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(request.path, '/')

class TestSSOLoginUChileCallback(ModuleStoreTestCase):
    def setUp(self):
        super(TestSSOLoginUChileCallback, self).setUp()
        self.client = Client()
        with patch('common.djangoapps.student.models.cc.User.save'):
            self.user = UserFactory(
                username='testuser3',
                password='12345',
                email='test555@test.test')
            self.user2 = UserFactory(
                username='testuser22',
                password='12345',
                email='test2@uchile.cl')
        
    @patch('requests.get')
    def test_login_user_with_extradata(self, get):
        """
            Test normal process with extradata model
        """
        SSOLoginCuentaUChile.objects.create(user=self.user, username='test.name', is_active=True)
        SSOLoginExtraData.objects.create(user=self.user,document='0123456789',type_document='rut')
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                            namedtuple("Request",
                                      ["status_code",
                                       "json"])(200,
                                                lambda:{'data':{'getRowsPersona':{'status_code':200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'test.name', 'vigencia': '1'}],
                                                     "nombres": "TEST NAME",
                                                     'email': [{'email': 'test@test.test'}],
                                                     "indiv_id": "0111111111"}]}}})]
        self.assertEqual(SSOLoginCuentaUChile.objects.all().count(), 1)
        self.assertEqual(SSOLoginExtraData.objects.all().count(), 1)
        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={
                'ticket': 'testticket',
                'next': 'aHR0cHM6Ly9lb2wudWNoaWxlLmNsLw=='})
        self.assertEqual(result.status_code, 302)
        self.assertEqual(
            get.call_args_list[0][0][0],
            settings.SSOLOGIN_UCHILE_RESULT_VALIDATE)
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(request.path, '/')
        self.assertEqual(SSOLoginCuentaUChile.objects.all().count(), 1)
        self.assertEqual(SSOLoginExtraData.objects.all().count(), 1)

    @patch('requests.get')
    def test_login_user_wo_extradata(self, get):
        """
            Test normal process without extradata model
        """
        SSOLoginCuentaUChile.objects.create(user=self.user, username='test.name', is_active=True)
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                            namedtuple("Request",
                                      ["status_code",
                                       "json"])(200,
                                                lambda:{'data':{'getRowsPersona':{'status_code':200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'test.name', 'vigencia': '1'}],
                                                     "nombres": "TEST NAME",
                                                     'email': [{'email': 'test@test.test'}],
                                                     "indiv_id": "0111111111"}]}}})]
        self.assertEqual(SSOLoginCuentaUChile.objects.all().count(), 1)
        self.assertEqual(SSOLoginExtraData.objects.all().count(), 0)
        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={
                'ticket': 'testticket',
                'next': 'aHR0cHM6Ly9lb2wudWNoaWxlLmNsLw=='})
        self.assertEqual(result.status_code, 302)
        self.assertEqual(
            get.call_args_list[0][0][0],
            settings.SSOLOGIN_UCHILE_RESULT_VALIDATE)
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(request.path, '/sso/verification_form')
        self.assertEqual(SSOLoginCuentaUChile.objects.all().count(), 1)
        self.assertEqual(SSOLoginExtraData.objects.all().count(), 0)

    @patch('requests.get')
    def test_login_user_sso_no_active(self, get):
        """
            Test callback when user dont have active sso account
        """
        SSOLoginCuentaUChile.objects.create(user=self.user, username='test.name', is_active=False)
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                            namedtuple("Request",
                                      ["status_code",
                                       "json"])(200,
                                                lambda:{'data':{'getRowsPersona':{'status_code':200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'test.name', 'vigencia': '1'}],
                                                     "nombres": "TEST NAME",
                                                     'email': [{'email': 'test@test.test'}],
                                                     "indiv_id": "0111111111"}]}}})]
        self.assertEqual(SSOLoginCuentaUChile.objects.all().count(), 1)
        self.assertEqual(SSOLoginExtraData.objects.all().count(), 0)
        self.assertEqual(SSOLoginCuentaUChileRegistration.objects.all().count(), 0)
        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={
                'ticket': 'testticket',
                'next': 'aHR0cHM6Ly9lb2wudWNoaWxlLmNsLw=='})
        self.assertEqual(result.status_code, 302)
        self.assertEqual(
            get.call_args_list[0][0][0],
            settings.SSOLOGIN_UCHILE_RESULT_VALIDATE)
        request = urllib.parse.urlparse(result.url)
        args = urllib.parse.parse_qs(request.query)
        self.assertEqual(request.path, '/sso/verification_pending')
        self.assertEqual(
            args['mail'][0],
            self.user.email)
        self.assertEqual(SSOLoginCuentaUChile.objects.all().count(), 1)
        self.assertEqual(SSOLoginExtraData.objects.all().count(), 0)
        self.assertEqual(SSOLoginCuentaUChileRegistration.objects.all().count(), 1)

    @patch('requests.get')
    def test_login_create_user(self, get):
        """
            Test create user normal process
        """
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                           namedtuple("Request",
                                      ["status_code",
                                       "json"])(200,
                                                lambda:{'data':{'getRowsPersona':{'status_code':200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'test.name', 'vigencia': '1'}],
                                                     "nombres": "TEST NAME",
                                                     'email': [{'email': 'test@test.test'}],
                                                     "indiv_id": "0111111111"}]}}})]

        self.assertEqual(SSOLoginCuentaUChile.objects.all().count(), 0)
        self.assertFalse(User.objects.filter(email="test@test.test").exists())
        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={
                'ticket': 'testticket'})
        self.assertEqual(SSOLoginCuentaUChile.objects.all().count(), 1)
        ssologin_user = SSOLoginCuentaUChile.objects.get(username="test.name")
        self.assertEqual(ssologin_user.user.email, 'test@test.test')
        self.assertTrue(ssologin_user.is_active)
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.path, '/sso/verification_form')

    @patch('requests.get')
    def test_login_create_ssologin_user(self, get):
        """
            Test create ssologin user normal process
        """
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                           namedtuple("Request",
                                      ["status_code",
                                       "json"])(200,
                                                lambda:{'data':{'getRowsPersona':{'status_code':200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'test.name', 'vigencia': '1'}],
                                                     "nombres": "TEST NAME",
                                                     'email': [{'email': self.user.email}],
                                                     "indiv_id": "0111111111"}]}}})]

        self.assertEqual(SSOLoginCuentaUChile.objects.all().count(), 0)
        self.assertEqual(SSOLoginCuentaUChileRegistration.objects.all().count(), 0)
        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={
                'ticket': 'testticket'})
        self.assertEqual(SSOLoginCuentaUChile.objects.all().count(), 1)
        self.assertEqual(SSOLoginCuentaUChileRegistration.objects.all().count(), 1)
        ssologin_user = SSOLoginCuentaUChile.objects.get(username="test.name")
        self.assertEqual(ssologin_user.user.email, self.user.email)
        self.assertFalse(ssologin_user.is_active)
        request = urllib.parse.urlparse(result.url)
        args = urllib.parse.parse_qs(request.query)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.path, '/sso/verification_pending')
        self.assertEqual(
            args['mail'][0],
            self.user.email)

    @patch('requests.get')
    def test_login_error_create_user(self, get):
        """
            Test callback when ocurr an error to create user
        """
        SSOLoginCuentaUChile.objects.create(user=self.user, username='test2.name', is_active=True)
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                           namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code':200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'test.name', 'vigencia': '1'}],
                                                     "nombres": "TEST NAME",
                                                     'email': [{'email': self.user.email}],
                                                     "indiv_id": "0111111111"}]}}}))]

        self.assertEqual(SSOLoginCuentaUChile.objects.all().count(), 1)
        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={
                'ticket': 'testticket'})
        self.assertEqual(SSOLoginCuentaUChile.objects.all().count(), 1)
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.path, '/eol_sso_login/uchile_login/')

    def test_get_or_create_user(self):
        """
            Test all cases of get_or_create_user function
        """
        emails = ['test@test.cl', 'test@uchile.cl']
        user_data = {
            'rut': '0111111111',
            'username': 'test.name',
            'nombres': 'TEST NAME',
            'apellidoPaterno': 'TESTLASTNAME',
            'apellidoMaterno': 'TESTLASTNAME',
            'emails': emails
        }
        # create user with @uchile.cl, when there are exists users
        self.assertFalse(User.objects.filter(email__in=emails).exists())
        user, created = SSOUChile().get_or_create_user(user_data)
        self.assertTrue(created)
        self.assertTrue(user.email, 'test@uchile.cl')
        SSOLoginCuentaUChile.objects.create(user=user, is_active=True, username='test')
        
        # get valid user with @uchile.cl, when exists @uchile.cl user
        emails.append(self.user2.email)
        user_data['emails'] = emails
        user, created = SSOUChile().get_or_create_user(user_data)
        self.assertFalse(created)
        self.assertTrue(user.email, self.user2.email)
        SSOLoginCuentaUChile.objects.create(user=user, is_active=True, username='test2')

        # get valid user, when exists user
        emails.append(self.user.email)
        user_data['emails'] = emails
        user, created = SSOUChile().get_or_create_user(user_data)
        self.assertFalse(created)
        self.assertTrue(user.email, self.user.email)
        SSOLoginCuentaUChile.objects.create(user=user, is_active=True, username='test3')

        # create user @uchile.cl, when there are no valid users but there are still valid emails (@uchile.cl)
        emails.append('test3@uchile.cl')
        user_data['emails'] = emails
        user, created = SSOUChile().get_or_create_user(user_data)
        self.assertTrue(created)
        self.assertTrue(user.email, 'test3@uchile.cl')
        SSOLoginCuentaUChile.objects.create(user=user, is_active=True, username='test4')

        # create user @uchile.cl, when there are no valid users but there are still valid emails
        user, created = SSOUChile().get_or_create_user(user_data)
        self.assertTrue(created)
        self.assertTrue(user.email, emails[0])
        SSOLoginCuentaUChile.objects.create(user=user, is_active=True, username='test5')

        # user is None, when there are not valid emails to get or create user
        user, created = SSOUChile().get_or_create_user(user_data)
        self.assertFalse(created)
        self.assertIsNone(user)

    @patch('requests.get')
    def test_login_error_to_get_data(self, get):
        """
            Test create user when fail to get data from ph api
        """
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                           namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':None}}))]


        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={'ticket': 'testticket'})
        self.assertFalse(SSOLoginCuentaUChile.objects.filter(username="test.name").exists())
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.path, '/eol_sso_login/uchile_login/')

    @patch('requests.get')
    def test_login_error_to_get_data_2(self, get):
        """
            Test create user when fail to get data from ph api
        """
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                           namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code': 200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [],
                                                     "nombres": "TEST NAME",
                                                     'email': [{'email': 'test@test.test'}],
                                                     "indiv_id": "0112223334"}]}}}))]


        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={'ticket': 'testticket'})
        self.assertFalse(SSOLoginCuentaUChile.objects.filter(username="test.name").exists())
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.path, '/eol_sso_login/uchile_login/')

    @patch('requests.get')
    def test_login_error_to_get_data_3(self, get):
        """
            Test create user when fail to get data from ph api
        """
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                           namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code': 200,'persona':[]}}}))]


        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={'ticket': 'testticket'})
        self.assertFalse(SSOLoginCuentaUChile.objects.filter(username="test.name").exists())
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.path, '/eol_sso_login/uchile_login/')

    @patch('requests.get')
    def test_login_error_to_get_data_4(self, get):
        """
            Test create user when fail to get data from ph api
        """
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                           namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code': 400}}}))]


        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={'ticket': 'testticket'})
        self.assertFalse(SSOLoginCuentaUChile.objects.filter(username="test.name").exists())
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.path, '/eol_sso_login/uchile_login/')

    @patch('requests.get')
    def test_login_error_to_get_data_5(self, get):
        """
            Test create user when fail to get data from ph api
        """
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                           namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code': 200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'test.name', 'vigencia': '0'}],
                                                     "nombres": "TEST NAME",
                                                     'email': [{'email': 'test@test.test'}],
                                                     "indiv_id": "0112223334"}]}}}))]


        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={'ticket': 'testticket'})
        self.assertFalse(SSOLoginCuentaUChile.objects.filter(username="test.name").exists())
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.path, '/eol_sso_login/uchile_login/')

    @patch('requests.get')
    def test_login_error_to_get_data_6(self, get):
        """
            Test create user when fail to get data from ph api
        """
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                           namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code': 200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'test.name', 'vigencia': '1'}],
                                                     "nombres": "TEST NAME",
                                                     'email': [],
                                                     "indiv_id": "0112223334"}]}}}))]


        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={'ticket': 'testticket'})
        self.assertFalse(SSOLoginCuentaUChile.objects.filter(username="test.name").exists())
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.path, '/eol_sso_login/uchile_login/')

    @patch('requests.get')
    def test_login_error_to_get_data_7(self, get):
        """
            Test create user when fail to get data from ph api
        """
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                           namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code': 200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'test.name', 'vigencia': '1'}],
                                                     "nombres": "TEST NAME",
                                                     "indiv_id": "0112223334"}]}}}))]


        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={'ticket': 'testticket'})
        self.assertFalse(SSOLoginCuentaUChile.objects.filter(username="test.name").exists())
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.path, '/eol_sso_login/uchile_login/')



    @patch('requests.get')
    def test_login_create_user_wrong_email(self, get):
        """
            Test create user when email is wrong
        """
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('yes\ntest.name\n').encode('utf-8')),
                           namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code':200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'username', 'vigencia': '1'}],
                                                     "nombres": "TEST NAME",
                                                     'email': [{'email': 'test@test'}],
                                                     "indiv_id": "0112223334"}]}}}))]


        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={'ticket': 'testticket'})
        self.assertFalse(SSOLoginCuentaUChile.objects.filter(username="test.name").exists())
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.path, '/eol_sso_login/uchile_login/')

    @patch('requests.get')
    def test_login_wrong_ticket(self, get):
        """
            Test callback when ticket is wrong
        """
        # Assert requests.get calls
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "content"])(200,
                                                   ('no\n\n').encode('utf-8')),
                           namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code':200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'username'}],
                                                     "nombres": "TEST NAME",
                                                     'email': [{'email': 'test@test.test'}],
                                                     "indiv_id": "0112223334"}]}}}))]
        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={'ticket': 'testticket'})
        self.assertFalse(SSOLoginCuentaUChile.objects.filter(username="test.name").exists())
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.path, '/eol_sso_login/uchile_login/')

    @patch('requests.get')
    def test_login_wrong_username(self, get):
        """
            Test callback when username is wrong
        """
        # Assert requests.get calls
        get.side_effect = [
            namedtuple(
                "Request", [
                    "status_code", "content"])(
                200, ('yes\nwrongname\n').encode('utf-8')), 
            namedtuple("Request",
                ["status_code",
                "text"])(200,
                        json.dumps({'data':{'getRowsPersona':{'status_code':200,'persona':[]}}}))]
        result = self.client.get(
            reverse('eol_sso_login:uchile_callback'),
            data={'ticket': 'testticket'})
        self.assertFalse(SSOLoginCuentaUChile.objects.filter(username="test.name").exists())
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(request.path, '/eol_sso_login/uchile_login/')

    def test_generate_username(self):
        """
            Test callback generate username normal process
        """
        data = {
            'username': 'test.name',
            'apellidoMaterno': 'dd',
            'nombres': 'aa bb',
            'apellidoPaterno': 'cc',
            'rut': '0112223334',
            'email': 'null'
        }
        data['email'] =  str(uuid.uuid4()) + '@invalid.invalid'
        self.assertEqual(
            SSOUChile().create_user_by_data(dict(data)).username,
            'aa_cc')
        data['email'] =  str(uuid.uuid4()) + '@invalid.invalid'
        self.assertEqual(
            SSOUChile().create_user_by_data(dict(data)).username,
            'aa_cc_d')
        data['email'] =  str(uuid.uuid4()) + '@invalid.invalid'
        self.assertEqual(
            SSOUChile().create_user_by_data(dict(data)).username,
            'aa_cc_dd')
        data['email'] =  str(uuid.uuid4()) + '@invalid.invalid'
        self.assertEqual(
            SSOUChile().create_user_by_data(dict(data)).username,
            'aa_b_cc')
        data['email'] =  str(uuid.uuid4()) + '@invalid.invalid'
        self.assertEqual(
            SSOUChile().create_user_by_data(dict(data)).username,
            'aa_bb_cc')
        data['email'] =  str(uuid.uuid4()) + '@invalid.invalid'
        self.assertEqual(
            SSOUChile().create_user_by_data(dict(data)).username,
            'aa_b_cc_d')
        data['email'] =  str(uuid.uuid4()) + '@invalid.invalid'
        self.assertEqual(
            SSOUChile().create_user_by_data(dict(data)).username,
            'aa_b_cc_dd')
        data['email'] =  str(uuid.uuid4()) + '@invalid.invalid'
        self.assertEqual(
            SSOUChile().create_user_by_data(dict(data)).username,
            'aa_bb_cc_d')
        data['email'] =  str(uuid.uuid4()) + '@invalid.invalid'
        self.assertEqual(
            SSOUChile().create_user_by_data(dict(data)).username,
            'aa_bb_cc_dd')
        data['email'] =  str(uuid.uuid4()) + '@invalid.invalid'
        self.assertEqual(
            SSOUChile().create_user_by_data(dict(data)).username,
            'aa_cc1')
        data['email'] =  str(uuid.uuid4()) + '@invalid.invalid'
        self.assertEqual(
            SSOUChile().create_user_by_data(dict(data)).username,
            'aa_cc2')

    def test_long_name(self):
        """
            Test callback generate username long name
        """
        data = {
            'username': 'test.name',
            'apellidoMaterno': 'ff',
            'nombres': 'a2345678901234567890123 bb',
            'apellidoPaterno': '4567890',
            'rut': '0112223334',
            'email': 'test@test.test'
        }

        self.assertEqual(SSOUChile().create_user_by_data(
            data).username, 'a2345678901234567890123_41')

    def test_null_lastname(self):
        """
            Test callback generate username when lastname is null
        """
        user_data = {
            "nombres": "Name",
            "apellidoPaterno": None,
            "apellidoMaterno": None}
        self.assertEqual(
            SSOUChile().generate_username(user_data),
            "Name_")

        user_data = {
            "nombres": "Name",
            "apellidoPaterno": "Last",
            "apellidoMaterno": None}
        self.assertEqual(
            SSOUChile().generate_username(user_data),
            "Name_Last")

    def test_whitespace_lastname(self):
        """
            Test callback generate username when lastname has too much whitespace
        """
        user_data = {
            "nombres": "Name",
            "apellidoPaterno": "          Last    Last2      ",
            "apellidoMaterno": '    Last2      '}
        self.assertEqual(
            SSOUChile().generate_username(user_data),
            "Name_Last")

    def test_long_name_middle(self):
        """
            Test callback generate username when long name middle
        """
        data = {
            'username': 'test.name',
            'apellidoMaterno': 'ff',
            'nombres': 'a23456789012345678901234 bb',
            'apellidoPaterno': '4567890',
            'rut': '0112223334',
            'email': 'test@test.test'
        }
        self.assertEqual(SSOUChile().create_user_by_data(
            data).username, 'a234567890123456789012341')

class TestSSOLoginUChileVerificationPending(TestCase):
    def setUp(self):
        self.client = Client()

    def test_get(self):
        """
            test get method 
        """
        result = self.client.get(reverse('eol_sso_login:verification-pending'),
                                data={'mail': 'test@test.ts',})
        self.assertEqual(result.status_code, 200)

        result = self.client.get(reverse('eol_sso_login:verification-pending'))
        self.assertEqual(result.status_code, 200)

    def test_post(self):
        """
            test post method 
        """
        result = self.client.post(reverse('eol_sso_login:verification-pending'))
        self.assertEqual(result.status_code, 405)

class TestSSOLoginUChileVerification(TestCase):
    def setUp(self):
        self.client = Client()
        with patch('common.djangoapps.student.models.cc.User.save'):
            self.user = UserFactory(
                username='testuser',
                password='12345',
                email='test@test.test')

    def test_get(self):
        """
            test get method normal process
        """
        verification_id = uuid.uuid4().hex
        SSOLoginCuentaUChileRegistration.objects.create(
            user=self.user,
            username='test.name',
            activation_key=verification_id
            )
        SSOLoginCuentaUChile.objects.create(user=self.user, username='test.name', is_active=False)
        result = self.client.get(reverse('eol_sso_login:verification'),
                                data={'id': verification_id})
        self.assertEqual(result.status_code, 200)
        ssologin_register = SSOLoginCuentaUChileRegistration.objects.get(user=self.user)
        ssologin_user = SSOLoginCuentaUChile.objects.get(user=self.user)
        self.assertIsNotNone(ssologin_register.activation_timestamp)
        self.assertTrue(ssologin_user.is_active)
    
    def test_get_sso_user_no_exists(self):
        """
            test get method when ssologin user doesnt exists
        """
        verification_id = uuid.uuid4().hex
        SSOLoginCuentaUChileRegistration.objects.create(
            user=self.user,
            username='test.name',
            activation_key=verification_id
            )
        result = self.client.get(reverse('eol_sso_login:verification'),
                                data={'id': verification_id})
        self.assertEqual(result.status_code, 200)
        ssologin_register = SSOLoginCuentaUChileRegistration.objects.get(user=self.user)
        self.assertIsNotNone(ssologin_register.activation_timestamp)

    def test_get_wrong_uuid(self):
        """
            test get method when verification id doesnt exists
        """
        verification_id = uuid.uuid4().hex
        SSOLoginCuentaUChileRegistration.objects.create(
            user=self.user,
            username='test.name',
            activation_key=verification_id
            )
        result = self.client.get(reverse('eol_sso_login:verification'),
                                data={'id': uuid.uuid4().hex})
        self.assertEqual(result.status_code, 404)
        ssologin_register = SSOLoginCuentaUChileRegistration.objects.get(user=self.user)
        self.assertIsNone(ssologin_register.activation_timestamp)

    def test_get_no_uuid(self):
        """
            test get method no params
        """
        verification_id = uuid.uuid4().hex
        SSOLoginCuentaUChileRegistration.objects.create(
            user=self.user,
            username='test.name',
            activation_key=verification_id
            )
        result = self.client.get(reverse('eol_sso_login:verification'))
        self.assertEqual(result.status_code, 404)
        ssologin_register = SSOLoginCuentaUChileRegistration.objects.get(user=self.user)
        self.assertIsNone(ssologin_register.activation_timestamp)

    def test_post(self):
        """
            test post method
        """
        result = self.client.post(reverse('eol_sso_login:verification'))
        self.assertEqual(result.status_code, 405)

class TestSSOLoginUChileVerificationData(TestCase):
    def setUp(self):
        self.client = Client()
        with patch('common.djangoapps.student.models.cc.User.save'):
            self.user = UserFactory(
                username='testuser',
                password='12345',
                email='test@test.test')
            self.user2 = UserFactory(
                username='testuser2',
                password='12345',
                email='test2@test.test')
        self.client.login(username='testuser', password='12345')

    def test_get(self):
        """
            test get method normal process
        """
        result = self.client.get(reverse('eol_sso_login:verification-data'))
        self.assertEqual(result.status_code, 200)

    def test_get_anonymous(self):
        """
            test get method anonymous user
        """
        client = Client()
        result = client.get(reverse('eol_sso_login:verification-data'))
        self.assertEqual(result.status_code, 302)
        request = urllib.parse.urlparse(result.url)
        self.assertEqual(request.path, '/')

    def test_post(self):
        """
            test update user profile data
        """
        post_data = {
            'country': "CL",
            'level_of_education': 'p',
            'gender': 'm',
            'year_of_birth': '1994',
            'document': 'ASDQWE',
            'type_document': 'passport'
        }
        self.assertEqual(SSOLoginExtraData.objects.all().count(), 0)
        result = self.client.post(reverse('eol_sso_login:verification-data'), post_data)
        self.assertEqual(SSOLoginExtraData.objects.all().count(), 1)
        ssologin_data = SSOLoginExtraData.objects.get(user=self.user)
        self.assertEqual(ssologin_data.document, post_data['document'])
        self.assertEqual(ssologin_data.type_document, post_data['type_document'])
        self.user.refresh_from_db()
        self.assertEqual(self.user.profile.year_of_birth, int(post_data['year_of_birth']))
        self.assertEqual(self.user.profile.gender, post_data['gender'])
        self.assertEqual(self.user.profile.level_of_education, post_data['level_of_education'])

    def test_post_exists_extradata(self):
        """
            test update user profile data, when user already have extradata model
        """
        post_data = {
            'country': "CL",
            'level_of_education': 'p',
            'gender': 'm',
            'year_of_birth': '1994',
            'document': 'ASDQWE',
            'type_document': 'passport'
        }
        ssologin_data = SSOLoginExtraData.objects.create(user=self.user,document='0123456789',type_document='rut')
        result = self.client.post(reverse('eol_sso_login:verification-data'), post_data)
        self.assertEqual(SSOLoginExtraData.objects.all().count(), 1)
        ssologin_data.refresh_from_db()
        self.assertEqual(ssologin_data.document, post_data['document'])
        self.assertEqual(ssologin_data.type_document, post_data['type_document'])
        self.user.refresh_from_db()
        self.assertEqual(self.user.profile.year_of_birth, int(post_data['year_of_birth']))
        self.assertEqual(self.user.profile.gender, post_data['gender'])
        self.assertEqual(self.user.profile.level_of_education, post_data['level_of_education'])
    
    def test_post(self):
        """
            test post method when user is anonymous
        """
        client = Client()
        result = client.post(reverse('eol_sso_login:verification-data'))
        self.assertEqual(result.status_code, 404)


    def test_post_data_valid(self):
        """
            test all cases in validation function
        """
        post_data = {
            'country': "CL",
            'level_of_education': 'p',
            'gender': 'm',
            'year_of_birth': '1994',
            'document': 'ASDQWE',
            'type_document': 'passport'
        }
        profile_sttgs = SSOLoginUChileVerificationData().get_profile_settings()
        result = SSOLoginUChileVerificationData().data_valid(post_data, profile_sttgs, self.user)
        self.assertTrue(result)

        # missing key
        aux_data = post_data.copy()
        del aux_data['country']
        result = SSOLoginUChileVerificationData().data_valid(aux_data, profile_sttgs, self.user)
        self.assertFalse(result)

        # wrong counrty
        aux_data = post_data.copy()
        aux_data['country'] = 'qwe123'
        result = SSOLoginUChileVerificationData().data_valid(aux_data, profile_sttgs, self.user)
        self.assertFalse(result)

        # wrong gender
        aux_data = post_data.copy()
        aux_data['gender'] = 'qwe123'
        result = SSOLoginUChileVerificationData().data_valid(aux_data, profile_sttgs, self.user)
        self.assertFalse(result)

        # wrong level_of_education
        aux_data = post_data.copy()
        aux_data['level_of_education'] = 'qwe123'
        result = SSOLoginUChileVerificationData().data_valid(aux_data, profile_sttgs, self.user)
        self.assertFalse(result)

        # wrong year_of_birth
        aux_data = post_data.copy()
        aux_data['year_of_birth'] = 'qwe123'
        result = SSOLoginUChileVerificationData().data_valid(aux_data, profile_sttgs, self.user)
        self.assertFalse(result)

        # wrong year_of_birth
        aux_data = post_data.copy()
        aux_data['year_of_birth'] = '1'
        result = SSOLoginUChileVerificationData().data_valid(aux_data, profile_sttgs, self.user)
        self.assertFalse(result)

        # wrong type_document
        aux_data = post_data.copy()
        aux_data['type_document'] = 'cccc'
        result = SSOLoginUChileVerificationData().data_valid(aux_data, profile_sttgs, self.user)
        self.assertFalse(result)

        # len document equals zero
        aux_data = post_data.copy()
        aux_data['document'] = ''
        result = SSOLoginUChileVerificationData().data_valid(aux_data, profile_sttgs, self.user)
        self.assertFalse(result)
        
        # wrong len document
        aux_data = post_data.copy()
        aux_data['document'] = 'a'
        result = SSOLoginUChileVerificationData().data_valid(aux_data, profile_sttgs, self.user)
        self.assertFalse(result)

        # wrong document
        aux_data = post_data.copy()
        aux_data['type_document'] = 'dni'
        aux_data['document'] = 'PASDQWE-@ASD'
        result = SSOLoginUChileVerificationData().data_valid(aux_data, profile_sttgs, self.user)
        self.assertFalse(result)

        # document wrong rut
        aux_data = post_data.copy()
        aux_data['type_document'] = 'rut'
        aux_data['document'] = '1234532'
        result = SSOLoginUChileVerificationData().data_valid(aux_data, profile_sttgs, self.user)
        self.assertFalse(result)

        # document wrong rut
        aux_data = post_data.copy()
        aux_data['type_document'] = 'rut'
        aux_data['document'] = 'asdadasd'
        result = SSOLoginUChileVerificationData().data_valid(aux_data, profile_sttgs, self.user)
        self.assertFalse(result)

        # already exists document
        SSOLoginExtraData.objects.create(
            document=post_data['document'], 
            type_document=post_data['type_document'], 
            user=self.user)
        aux_data = post_data.copy()
        aux_data['type_document'] = 'passport'
        aux_data['document'] = 'P123456'
        
        SSOLoginExtraData.objects.create(
            document=aux_data['document'], 
            type_document=aux_data['type_document'], 
            user=self.user2)

        result = SSOLoginUChileVerificationData().data_valid(aux_data, profile_sttgs, self.user)
        self.assertFalse(result)

class TestSSOLoginAPI(TestCase):
    def setUp(self):
        self.client = Client()
        with patch('common.djangoapps.student.models.cc.User.save'):
            self.user = UserFactory(
                username='testuser',
                password='12345',
                email='test@test.test')

    def test_registration_validation(self):
        """
            test post method normal process
        """
        post_data = {
            'document': 'ASDQWE',
            'type_document': 'passport'
        }
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'success', 
            'have_sso': False
            }
        self.assertEqual(respose, expected)

    @patch('requests.get')
    def test_registration_validation_have_sso(self, get):
        """
            test post method normal process when user have ssologin
        """
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code': 200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'test.name', 'vigencia': '1'}],
                                                     "nombres": "TEST NAME",
                                                     'email': [{'email': 'test@test.test'}],
                                                     "indiv_id": "0111111111"}]}}}))]
        
        post_data = {
            'document': '11111111-1',
            'type_document': 'rut'
        }
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'success', 
            'have_sso': True
            }
        self.assertEqual(respose, expected)

    @patch('requests.get')
    def test_registration_validation_no_have_sso(self, get):
        """
            test post method normal process havent ssologin
        """
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code': 200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [],
                                                     "nombres": "TEST NAME",
                                                     'email': [{'email': 'test@test.test'}],
                                                     "indiv_id": "0111111111"}]}}}))]
        
        post_data = {
            'document': '11111111-1',
            'type_document': 'rut'
        }
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'success', 
            'have_sso': False
            }
        self.assertEqual(respose, expected)

    @patch('requests.get')
    def test_registration_validation_no_have_sso_2(self, get):
        """
            test post method normal process havent ssologin
        """
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code': 200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'test.name', 'vigencia': '0'}],
                                                     "nombres": "TEST NAME",
                                                     'email': [{'email': 'test@test.test'}],
                                                     "indiv_id": "0111111111"}]}}}))]
        
        post_data = {
            'document': '11111111-1',
            'type_document': 'rut'
        }
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'success', 
            'have_sso': False
            }
        self.assertEqual(respose, expected)

    @patch('requests.get')
    def test_registration_validation_no_have_sso_3(self, get):
        """
            test post method normal process havent ssologin
        """
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code': 200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'test.name', 'vigencia': '1'}],
                                                     "nombres": "TEST NAME",
                                                     'email': [],
                                                     "indiv_id": "0111111111"}]}}}))]
        
        post_data = {
            'document': '11111111-1',
            'type_document': 'rut'
        }
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'success', 
            'have_sso': False
            }
        self.assertEqual(respose, expected)

    @patch('requests.get')
    def test_registration_validation_no_have_sso_4(self, get):
        """
            test post method normal process havent ssologin
        """
        get.side_effect = [namedtuple("Request",
                                      ["status_code",
                                       "text"])(200,
                                                json.dumps({'data':{'getRowsPersona':{'status_code': 200,'persona':[
                                                    {"paterno": "TESTLASTNAME",
                                                     "materno": "TESTLASTNAME",
                                                     'pasaporte': [{'usuario':'test.name', 'vigencia': '1'}],
                                                     "nombres": "TEST NAME",
                                                     "indiv_id": "0111111111"}]}}}))]
        
        post_data = {
            'document': '11111111-1',
            'type_document': 'rut'
        }
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'success', 
            'have_sso': False
            }
        self.assertEqual(respose, expected)

    def test_registration_validation_exists_user(self):
        """
            test post method when user already exists
        """
        
        post_data = {
            'document': '11111111-1',
            'type_document': 'rut'
        }
        SSOLoginExtraData.objects.create(
            document='0111111111', 
            type_document=post_data['type_document'], 
            user=self.user)
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'error',
            'error': 'document_exists',
            'have_sso': False
            }
        self.assertEqual(respose, expected)
        SSOLoginCuentaUChile.objects.create(
            user=self.user,
            username='test',
            is_active=True
        )
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'error',
            'error': 'document_exists',
            'have_sso': True
            }
        self.assertEqual(respose, expected)

    def test_registration_validation_wrong_rut(self):
        """
            test post method when document(type rut) is wrong
        """
        
        post_data = {
            'document': '234567876',
            'type_document': 'rut'
        }
        
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'error',
            'error': 'wrong_rut'
            }
        self.assertEqual(respose, expected)
        post_data = {
            'document': 'ASDSAFs',
            'type_document': 'rut'
        }
        
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'error',
            'error': 'wrong_rut'
            }
        self.assertEqual(respose, expected)

    def test_registration_validation_wrong_type_document(self):
        """
            test post method when type document is empty
        """
        
        post_data = {
            'document': 'PASDASF',
            'type_document': ''
        }
        
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'error',
            'error': 'no_type_document'
            }
        self.assertEqual(respose, expected)

    def test_registration_validation_wrong_document_length(self):
        """
            test post method when document is short or long
        """
        
        post_data = {
            'document': 'PAS',
            'type_document': 'passport'
        }
        
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'error',
            'error': 'document_length'
            }
        self.assertEqual(respose, expected)
        post_data = {
            'document': 'P12345678901234567890',
            'type_document': 'passport'
        }
        
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'error',
            'error': 'document_length'
            }
        self.assertEqual(respose, expected)

    def test_registration_validation_no_document(self):
        """
            test post method when document is empty
        """
        
        post_data = {
            'document': '',
            'type_document': 'passport'
        }
        
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'error',
            'error': 'no_document'
            }
        self.assertEqual(respose, expected)

    def test_registration_validation_missing_params(self):
        """
            test post method normal when missing params
        """
        
        post_data = {
            'document': 'asdadad',
        }
        
        result = self.client.post(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 400)

    def test_registration_validation_get(self):
        """
            test get method 
        """
        
        post_data = {
            'document': '',
            'type_document': 'passport'
        }
        
        result = self.client.get(reverse('eol_sso_login:api-registration'), post_data)
        self.assertEqual(result.status_code, 400)
    
    def test_check_email(self):
        """
            test check email api normal process
        """ 
        post_data = {
            'email': 'testtest@test.ts'
        }
        result = self.client.post(reverse('eol_sso_login:api-email'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'success', 
            'exists': False,
            'have_sso': False,
            'active': False,
            'sso_active': False,
            }
        self.assertEqual(respose, expected)

    def test_check_email_exists_user(self):
        """
            test check email api normal process when already user exists
        """ 
        post_data = {
            'email': self.user.email
        }
        result = self.client.post(reverse('eol_sso_login:api-email'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'success', 
            'exists': True,
            'have_sso': False,
            'active': True,
            'sso_active': False,
            }
        self.assertEqual(respose, expected)

    def test_check_email_exists_sso_user(self):
        """
            test check email api normal process when already ssologin user exists
        """ 
        post_data = {
            'email': self.user.email
        }
        SSOLoginCuentaUChile.objects.create(
            user=self.user,
            username='test',
            is_active=True
        )
        result = self.client.post(reverse('eol_sso_login:api-email'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'success', 
            'exists': True,
            'have_sso': True,
            'active': True,
            'sso_active': True,
            }
        self.assertEqual(respose, expected)
    
    def test_check_email_no_email(self):
        """
            test check email api when email is empty
        """ 
        post_data = {
            'email': ''
        }
        result = self.client.post(reverse('eol_sso_login:api-email'), post_data)
        self.assertEqual(result.status_code, 200)
        respose = json.loads(result._container[0].decode())
        expected = {
            'result': 'error', 
            'error': 'no_email',
            }
        self.assertEqual(respose, expected)

    def test_check_email_missing_params(self):
        """
            test check email api when missing params
        """ 
        post_data = {}
        result = self.client.post(reverse('eol_sso_login:api-email'), post_data)
        self.assertEqual(result.status_code, 400)

    def test_check_email_get(self):
        """
            test check email api GET method
        """ 
        post_data = {}
        result = self.client.get(reverse('eol_sso_login:api-email'), post_data)
        self.assertEqual(result.status_code, 400)