from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from users.views import  *

urlpatterns = [
    path('login/', verify_otp_and_register, name='token_obtain_pair'),
    path('token-refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', logout, name='logout'),
    path('is_authenticated/', is_authenticated, name='is_authenticated'),
    path('register/', register, name='register'),
    path('profile/', UserProfileAPIView.as_view(), name='profile'),
]
