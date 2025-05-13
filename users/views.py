import random
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.decorators import api_view, permission_classes
from rest_framework.generics import  RetrieveAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from users.serializer import RegisterSerializer, UserUpdateSerializer
User = get_user_model()
# Create your views here.

# class CustomTokenObtainPairView(TokenObtainPairView):
#     def post(self, request, *args, **kwargs):
#         try:
#             response = super().post(request, *args, **kwargs)
#             tokens = response.data
#             access_token = tokens['access']
#             refresh_token = tokens['refresh']
#             res = Response({'success': True})
#             res.set_cookie(key='access_token', value=access_token, httponly=True, secure=True, samesite='None',
#                            path='/')
#             res.set_cookie(key='refresh_token', value=refresh_token, httponly=True, secure=True, samesite='None',
#                            path='/')
#             return res
#         except Exception as e:
#             return Response({'success': False}, status=400)
#
#
# class CustomTokenRefreshView(TokenRefreshView):
#     def post(self, request, *args, **kwargs):
#         try:
#             refresh_token = request.COOKIES.get('refresh_token')
#             request.data['refresh'] = refresh_token
#             response = super().post(request, *args, **kwargs)
#             tokens = response.data
#             access_token = tokens['access']
#             res = Response({'refreshed': True})
#             res.set_cookie(
#                 key='access_token',
#                 value=access_token,
#                 httponly=True,
#                 secure=True,
#                 samesite='None',
#                 path='/'
#             )
#             return res
#         except:
#             return Response({'success': False}, status=400)



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        refresh_token = request.data.get("refresh_token")

        if not refresh_token:
            return Response({"error": "Refresh token is required"}, status=400)

        token = RefreshToken(refresh_token)
        token.blacklist()

        return Response({"success": True, "message": "Logged out successfully"}, status=200)
    except Exception as e:
        return Response({"error": str(e)}, status=400)


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        phone_number = request.data.get('phone_number')

        if not email:
            return Response({"message": "Email topilmadi."}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=email).exists():
            return Response(
                {"error": "Bu email allaqachon ro'yxatdan o'tgan."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if User.objects.filter(phone_number=phone_number).exists():
            return Response(
                {"error": "Bu telefon raqam allaqachon ro'yxatdan o'tgan."},
                status=status.HTTP_400_BAD_REQUEST
            )
        otp = str(random.randint(10000, 99999))
        cache.set(f"otp_{email}", otp, timeout=300)

        if not send_otp_via_email(email, otp):
            return Response({"message": "Email yuborishda xatolik yuz berdi."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "OTP muvaffaqiyatli yuborildi"}, status=status.HTTP_200_OK)

def send_otp_via_email(email, otp):
    subject = "Tasdiqlash kodingiz"
    message = f"Sizning tasdiqlash kodingiz: {otp}"
    from_email = 'your_email@gmail.com'  # Same email as in settings
    try:
        send_mail(subject, message, from_email, [email])
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False




class VerifyOTPAndRegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')


        if not email or not otp :
            return Response(
                {"error": "Email, telefon raqam va OTP talab qilinadi."},
                status=status.HTTP_400_BAD_REQUEST
            )

        cached_otp = cache.get(f"otp_{email}")

        if cached_otp is None:
            return Response(
                {"message": "Siz 5 daqiqa ichida kodni kiritishingiz lozim edi."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if cached_otp != otp:
            return Response(
                {"message": "Xato kod terdingiz."},
                status=status.HTTP_400_BAD_REQUEST
            )



        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        cache.delete(f"otp_{email}")

        refresh = RefreshToken.for_user(user)
        return Response({
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh)
        }, status=status.HTTP_200_OK)

class LoginWithPhoneView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        phone_number = request.data.get('phone_number')
        password = request.data.get('password')

        if not phone_number or not password:
            return Response({"error": "Telefon raqam va parol talab qilinadi."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            return Response({"error": "Bunday foydalanuvchi topilmadi."}, status=status.HTTP_404_NOT_FOUND)

        if not user.check_password(password):
            return Response({"error": "Parol noto'g'ri."}, status=status.HTTP_400_BAD_REQUEST)

        refresh = RefreshToken.for_user(user)

        return Response({
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh)
        }, status=status.HTTP_200_OK)

class UserProfileAPIView(RetrieveAPIView):
    serializer_class = UserUpdateSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def is_authenticated(request):
    return Response({'authenticated': True})
