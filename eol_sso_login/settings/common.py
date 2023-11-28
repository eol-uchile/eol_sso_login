def plugin_settings(settings):
    ssologin_host = 'http://172.25.14.193'

    settings.SSOLOGIN_UCHILE_RESULT_VALIDATE = ssologin_host + ':9513/validate'
    settings.SSOLOGIN_UCHILE_REQUEST_URL = ssologin_host + ':9513/login'
    settings.SSOLOGIN_UCHILE_KEY = ''
    settings.SSOLOGIN_UCHILE_USER_INFO_URL = ''
