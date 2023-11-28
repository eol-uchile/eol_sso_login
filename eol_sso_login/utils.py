import json
import logging
import requests
from django.conf import settings
from itertools import cycle

logger = logging.getLogger(__name__)

def validarRut(rut):
    """
        Verify if the 'rut' is valid
    """
    rut = rut.upper().strip()
    rut = rut.replace("-", "")
    rut = rut.replace(".", "")
    aux = rut[:-1]
    dv = rut[-1:]

    revertido = list(map(int, reversed(str(aux))))
    factors = cycle(list(range(2, 8)))
    s = sum(d * f for d, f in zip(revertido, factors))
    res = (-s) % 11

    if str(res) == dv:
        return True
    elif dv == "K" and res == 10:
        return True
    else:
        return False

def check_rut_have_sso(rut):
    """
    Check if rut have sso
    """
    headers = {
        'AppKey': settings.SSOLOGIN_UCHILE_KEY,
        'Origin': settings.LMS_ROOT_URL
    }
    params = (('indiv_id', '"{}"'.format(rut)),)
    base_url = settings.SSOLOGIN_UCHILE_USER_INFO_URL
    result = requests.get(base_url, headers=headers, params=params)

    if result.status_code != 200:
        logger.error(
            "EOl_SSO_Login - Api Status Code Error, {} {}".format(
                result.request,
                result.request.headers))
        return False

    data = json.loads(result.text)
    if data["data"]["getRowsPersona"] is None:
        return False
    if data['data']['getRowsPersona']['status_code'] != 200:
        logger.error(
            "EOl_SSO_Login - Api Error: {}, body: {}, rut: {}".format(
                data['data']['getRowsPersona']['status_code'],
                result.text,
                rut))
        return False
    if len(data["data"]["getRowsPersona"]["persona"]) == 0:
        return False
    if len(data["data"]["getRowsPersona"]["persona"][0]['pasaporte']) == 0:
        return False
    return True