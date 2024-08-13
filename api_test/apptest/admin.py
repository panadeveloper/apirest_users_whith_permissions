from django.contrib import admin
from apptest.models import CustomUser
from rest_framework_simplejwt.token_blacklist.admin import OutstandingTokenAdmin
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

admin.site.register(CustomUser)