from pathlib import Path
from django.urls import path
from . import views

#URL Config
urlpatterns = [
    path('upload-image/', views.uploadImage),
    path('find-image/', views.findImage),
    path('accept-upload-image/', views.acceptUploadImage),
    path('get-images/', views.getAllImage),
    path('register/', views.Register_Users),
    path('login/', views.login_user),
    path('logout/', views.User_logout),
    path('email-verify/', views.verifyEmail, name="email-verify"),
    path('request-reset-email/', views.RequestPasswordReset,name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/', views.CheckRasswordToken, name='password-reset-confirm'),
    path('password-reset-complete', views.SetNewPassword,name='password-reset-complete'),
    path('testmail/', views.test_Email)

]