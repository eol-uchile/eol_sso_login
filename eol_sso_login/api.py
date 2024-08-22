import logging

from common.djangoapps.util.json_request import JsonResponse
from django.contrib.auth.models import User
from django.http import HttpResponse

from .models import SSOLoginCuentaUChile, SSOLoginExtraData
from .utils import validarRut, check_rut_have_sso


logger = logging.getLogger(__name__)

def registration_validation(request):
    """
        Validate document in register html
    """
    if request.method != "POST":
        return HttpResponse(status=400)
    if 'document' not in request.POST or 'type_document' not in request.POST:
        return HttpResponse(status=400)
    document = request.POST.get('document', '').upper().strip()
    type_document = request.POST.get('type_document', '').strip()
    if len(document) == 0:
        return JsonResponse({'result': 'error', 'error':'no_document'})
    if 5 > len(document) or len(document) > 20:
        return JsonResponse({'result': 'error', 'error':'document_length'})
    if len(type_document) == 0:
        return JsonResponse({'result': 'error', 'error':'no_type_document'})
    if type_document != 'rut' and not document.isalnum():
        return JsonResponse({'result': 'error', 'error':'wrong_document'})
    try:
        if type_document == 'rut' and not validarRut(document):
            return JsonResponse({'result': 'error', 'error':'wrong_rut'})
    except ValueError:
        return JsonResponse({'result': 'error', 'error':'wrong_rut'})

    if type_document == 'rut':
        document = document.replace("-", "")
        document = document.replace(".", "")
        while len(document) < 10:
            document = "0" + document

    check_sso = False
    if SSOLoginExtraData.objects.filter(document=document, type_document=type_document).exists():
        ssologin_data = SSOLoginExtraData.objects.get(document=document, type_document=type_document)
        try:
            ssologin_user = SSOLoginCuentaUChile.objects.get(user=ssologin_data.user)
            check_sso = ssologin_user.is_active
        except SSOLoginCuentaUChile.DoesNotExist:
            pass
        return JsonResponse({'result': 'error', 'error':'document_exists', 'have_sso': check_sso})

    if type_document == "rut":
        try:
            check_sso = check_rut_have_sso(document)
        except Exception as e:
            logger.info('Eol_SSO_Login - Error registration_validation api, data:{}, error: {}'.format(request.POST, str(e)))
            pass

    return JsonResponse({'result': 'success', 'have_sso': check_sso})

def check_email(request):
    """
        Validate if email exists in login html
    """
    if request.method != "POST":
        return HttpResponse(status=400)
    if 'email' not in request.POST:
        return HttpResponse(status=400)
    email = request.POST.get('email', '').lower().strip()
    if len(email) == 0:
        return JsonResponse({'result': 'error', 'error':'no_email'})
    
    exists = False
    have_sso = False
    active = False
    sso_active = False
    if User.objects.filter(email=email).exists():
        user = User.objects.get(email=email)
        exists = True
        active = user.is_active
        try:
            ssologin_user = SSOLoginCuentaUChile.objects.get(user=user)
            have_sso = True
            sso_active = ssologin_user.is_active
        except SSOLoginCuentaUChile.DoesNotExist:
            pass

    return JsonResponse({
        'result': 'success', 
        'exists': exists,
        'have_sso': have_sso,
        'active': active,
        'sso_active': sso_active,
        })
