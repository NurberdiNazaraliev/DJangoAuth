from django.contrib.auth.backends import BaseBackend
from django.shortcuts import render, get_object_or_404
from django.template.loader import render_to_string
from rest_framework import generics, status, views, permissions
from rest_framework.authentication import TokenAuthentication
from rest_framework.decorators import api_view
from rest_framework.generics import CreateAPIView, ListAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
##from .models import CustomUser
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.contrib.auth import authenticate, logout, login, get_user_model
from django.shortcuts import redirect
from django.http import HttpResponsePermanentRedirect, JsonResponse
import os
from django.contrib import messages
from .serializers import *
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import auth, User
from django.contrib.auth.models import auth, User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.mail import EmailMessage
from typing import Protocol
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, get_user_model
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from rest_framework import generics, permissions
from rest_framework import authentication, permissions
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes


# Create your views here.
from rest_framework.authtoken.models import Token

# Assuming `user` is the user object for which you want to generate a token
class SignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == status.HTTP_201_CREATED:
            user = User.objects.get(username=request.data['username'])
            token, created = Token.objects.get_or_create(user=user)
            response.data['token'] = token.key

            send_verification_email(user, request)
        return response



class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)
        if user is not None:
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key})
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Get the user's token and delete it
        Token.objects.filter(user=request.user).delete()
        return Response({'message': 'Successfully logged out'})


class MyProtectedView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Your view logic here
        return Response({'message': 'This is a protected view'})


def verify_email(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        # Mark user as verified (You can set a flag in your User model)
        user.is_verified = True
        user.save()
        login_url = reverse('login') + '?verified=true'
        return JsonResponse({'message': 'Email verification successful, return to login page and login'})
    else:
        return render(request, 'verification_failed.html')








def send_verification_email(user,request):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    domain = get_current_site(request).domain
    verification_link = f"{domain}/verify/{uid}/{token}/"

    subject = 'Verify Your Email'
    message = render_to_string('verification_email.txt', {'user': user, 'verification_link': verification_link})
    send_mail(subject, message, 'authenticate636@gmail.com', [user.email])

def send_verification_email_again(request):
    email = request.POST.get('email')
    user = get_object_or_404(User, email=email)
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    domain = get_current_site(request).domain
    verification_link = f"{domain}/verify/{uid}/{token}/"

    subject = 'Verify Your Email'
    message = render_to_string('verification_email.txt', {'user': user, 'verification_link': verification_link})
    send_mail(subject, message, 'authenticate636@gmail.com', [user.email])