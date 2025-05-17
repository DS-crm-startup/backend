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
from django.conf import settings
from users.serializer import RegisterSerializer, UserUpdateSerializer
User = get_user_model()
# Create your views here.


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self,request):
        try:
            refresh_token = request.data.get("refresh_token")

            if not refresh_token:
                return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({"success": True, "message": "Logged out successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


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
    from_email = settings.EMAIL_HOST_USER
    try:
        send_mail(subject, message, from_email, [email])
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


class OtpSendViaEmail(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"message": "Email topilmadi."}, status=status.HTTP_400_BAD_REQUEST)
        otp1 = str(random.randint(10000, 99999))
        cache.set(f"otp_{email}", otp1, timeout=300)
        if not send_otp_via_email(email, otp1):
            return Response({"message": "Email yuborishda xatolik yuz berdi."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({"message": "OTP muvaffaqiyatli yuborildi"}, status=status.HTTP_200_OK)


class ResetPasswordCustomView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        serializer = RegisterSerializer(instance=request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'success': 'Password updated successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class VerifyOTPAndRegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')


        if not email or not otp :
            return Response(
                {"error": "Email va OTP talab qilinadi."},
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
                {"message": "Xato kod kiritdingiz."},
                status=status.HTTP_400_BAD_REQUEST
            )
        cache.delete(f"otp_{email}")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            serializer = RegisterSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save()
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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
