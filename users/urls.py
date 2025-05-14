from django.contrib.auth.views import PasswordResetView
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from users.views import  *

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify/', VerifyOTPAndRegisterView.as_view(), name='token_obtain_pair'),
    path('login/', LoginWithPhoneView.as_view(), name='token_obtain_pair'),
    path('token-refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', logout, name='logout'),
    path('is_authenticated/', is_authenticated, name='is_authenticated'),
    path('profile/', UserProfileAPIView.as_view(), name='profile'),
    path('send-otp/',OtpSendViaEmail.as_view(), name='send-otp'),
    path('reset-password/', ResetPasswordCustomView.as_view(), name='password_reset'),
]
