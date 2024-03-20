# -*- coding:utf-8 -*-
import logging
from django import forms
from .utils import validarRut
from .models import SSOLoginExtraData
from django.utils.translation import gettext_lazy as _
logger = logging.getLogger(__name__)

class ExtraInfoForm(forms.ModelForm):
    """
    The fields on this form are derived from the EdxLoginUser model in models.py.
    """
    class Meta(object):
        model = SSOLoginExtraData
        fields = ('type_document', 'document',)

    def __init__(self, *args, **kwargs):
        super(ExtraInfoForm, self).__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super(ExtraInfoForm, self).clean()
        document = self.cleaned_data.get("document").upper().strip()
        type_document = self.cleaned_data.get("type_document")
        if len(document) == 0:
            raise forms.ValidationError(_('Enter document number'))
        if 5 > len(document) or len(document) > 20:
            raise forms.ValidationError(_('Invalid document'))
        if len(type_document) == 0:
            raise forms.ValidationError(_('Enter document type'))
        if type_document != 'rut' and not document.isalnum():
            raise forms.ValidationError(_('Document only allows alphanumeric characters'))
        try:
            if type_document == 'rut' and not validarRut(document):
                raise forms.ValidationError(_('Incorrect Rut'))
        except ValueError:
            raise forms.ValidationError(_('Incorrect Rut'))

        if type_document == 'rut':
            document = document.replace("-", "")
            document = document.replace(".", "")
            while len(document) < 10:
                document = "0" + document
        if SSOLoginExtraData.objects.filter(document=document, type_document=type_document).exists():
            raise forms.ValidationError(_('Document already exists on platform'))
        return cleaned_data

    def save(self, commit=True):
        instance = super(ExtraInfoForm, self).save(commit=False)
        aux_document = self.cleaned_data.get("document").upper().strip()
        type_document = self.cleaned_data.get("type_document")
        if type_document == 'rut':
            aux_document = aux_document.replace("-", "")
            aux_document = aux_document.replace(".", "")
            while len(aux_document) < 10:
                aux_document = "0" + aux_document

        instance.document = aux_document
        instance.type_document = type_document
        if commit:
            instance.save()
        return instance
