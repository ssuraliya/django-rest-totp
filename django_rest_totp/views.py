from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.views import TokenRefreshView

from .exceptions import InvalidRefreshToken
from .serializers import OTPGenerateSerializer, OTPVerifySerializer


class OTPBaseView(generics.GenericAPIView):
    serializer_class = None

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class OTPGenerateViewStore(OTPBaseView):
    serializer_class = OTPGenerateSerializer


class OTPVerifyViewStore(OTPBaseView):
    serializer_class = OTPVerifySerializer


class UserTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)
        except InvalidToken as e:
            raise InvalidRefreshToken(detail=e.args[0])
        return response
