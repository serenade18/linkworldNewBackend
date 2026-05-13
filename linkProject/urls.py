"""
"""
from django.contrib import admin
from django.template.context_processors import static
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from linkApp.activation import ActivateAccountView
from linkApp.serializers import CustomTokenObtainPairView
from linkApp.views import UserViewSet, UserInfoView, ChangePasswordView
from linkProject import settings

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'kyc', KycViewSet, basename='kyc')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    # JWT Authentication
    path('api/gettoken/', CustomTokenObtainPairView.as_view(), name='gettoken'),
    path('api/refresh_token/', TokenRefreshView.as_view(), name='refresh_token'),
    path('api/verify_token/', TokenVerifyView.as_view(), name='verify_token'),
    path('api/userinfo/', UserInfoView.as_view(), name='userinfo'),
    path('api/userinfo/change-password/', ChangePasswordView.as_view(), name="change-password"),
    path('api/activate/<str:uidb64>/<str:token>/', ActivateAccountView.as_view(), name='activate-account'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
