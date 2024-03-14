from django.contrib import admin
from django.urls import path, include
from .views import *
urlpatterns = [

    path('login/', LoginView.as_view(), name="login"),
    path('signup/', SignupView.as_view(), name="signup"),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('protected/', MyProtectedView.as_view(), name='protected-view'),
    path('verify/<str:uidb64>/<str:token>/', verify_email, name='verify_email'),
    path('send-verification-email-again/', send_verification_email_again, name='send_verification_email_again'),


]