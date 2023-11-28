from django.contrib import admin
from .models import SSOLoginCuentaUChile, SSOLoginExtraData, SSOLoginCuentaUChileRegistration

# Register your models here.


class SSOLoginCuentaUChileAdmin(admin.ModelAdmin):
    raw_id_fields = ('user',)
    list_display = ('user', 'username', 'is_active', 'login_timestamp')
    search_fields = ['user__username', 'username']
    ordering = ['-id']

class SSOLoginExtraDataAdmin(admin.ModelAdmin):
    raw_id_fields = ('user',)
    list_display = ('document', 'type_document', 'user')
    search_fields = ['document', 'type_document', 'user__username']
    ordering = ['-id']

class SSOLoginCuentaUChileRegistrationAdmin(admin.ModelAdmin):
    raw_id_fields = ('user',)
    list_display = ('user', 'username', 'activation_key', 'activation_timestamp')
    search_fields = ['user__username', 'username', 'activation_key']
    ordering = ['-id']


admin.site.register(SSOLoginCuentaUChile, SSOLoginCuentaUChileAdmin)
admin.site.register(SSOLoginExtraData, SSOLoginExtraDataAdmin)
admin.site.register(
    SSOLoginCuentaUChileRegistration,
    SSOLoginCuentaUChileRegistrationAdmin)
