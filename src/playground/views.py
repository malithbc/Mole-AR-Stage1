import json
from json.decoder import JSONDecoder
from pickle import FALSE
from django.shortcuts import render
from django.http import HttpResponse, request
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth import login, logout
from django.contrib.auth.hashers import check_password
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.authtoken.models import Token

from .serializers import  ImageSerializer, TemporarySerializer, RegisterSerializer, SetNewPasswordSerializer

from .models import Image, TemporaryImage
from .utils import batch_extractor, extract_features, open_pickle, find_target_image_id, send_mail, read_file
import uuid
import os
import copy
import logging

logger = logging.getLogger('django')

# from playground import serializers

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def uploadImage(request):
    logger.info(request.data)
    token = request.user.auth_token
    user_id = token.user_id
    image_id = str(uuid.uuid1())
    request_data = request.data
    request_data ["image_id"] = image_id
    dict2 = copy.deepcopy(request_data)
    dict2.pop("object_3D")
    dict2.pop("mtl")
    temp_serializer = TemporarySerializer(data=dict2)

    if temp_serializer.is_valid():
        temp_serializer.save()
        search_image = TemporaryImage.objects.get(image_id=image_id)
        temp_image_path = str(TemporaryImage.get_image(search_image))
        target = find_target_image_id(temp_image_path)
        score = target[1]
        target_id = target[0]
        search_image.delete()
        os.remove(temp_image_path)

        if score>60:
            img = Image.objects.get(image_id= target_id)
            name = str(Image.get_image(img))
            dic = {"image-id": target_id, "name": name, "message": "Simiar image is in the database. Plaease check it"}
            return Response(dic)
        else:
            request_data ["user_id"] = user_id
            serializer = ImageSerializer(data=request_data)

            if serializer.is_valid():
                serializer.save()
                image = Image.objects.get(image_id=image_id)
                image_path = str(Image.get_image(image))
                batch_extractor(image_path, image_id)
                # os.remove(image_path)
                logger.info("Image uploaded successfully")
                return Response(serializer.data)

            else:
                logger.error(serializer.errors)
                return Response(serializer.errors)
    else:
        logger.error(temp_serializer.errors)
        return Response(temp_serializer.errors)
    


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def acceptUploadImage(request):
    logger.info(request.data)
    token = request.user.auth_token
    user_id = token.user_id
    image_id = str(uuid.uuid1())
    request_data = request.data
    request_data ["image_id"] = image_id
    request_data ["user_id"] = user_id
    serializer = ImageSerializer(data=request_data)

    if serializer.is_valid():
        serializer.save()
        image = Image.objects.get(image_id=image_id)
        image_path = str(Image.get_image(image))
        batch_extractor(image_path, image_id)
        # os.remove(image_path)
        logger.info("Image uploaded successfully")
        return Response(serializer.data)
    else:
        logger.error(serializer.errors)
        return Response(serializer.errors)


@api_view(['POST'])
@permission_classes([AllowAny])
def findImage(request):
    logger.info(request.data)
    image_id = str(uuid.uuid1())
    request_data = request.data
    request_data ["image_id"] = image_id
    serializer = TemporarySerializer(data=request_data)

    if serializer.is_valid():
        serializer.save()
        search_image = TemporaryImage.objects.get(image_id=image_id)
        image_path = str(TemporaryImage.get_image(search_image))
        target = find_target_image_id(image_path)
        target_id = target[0]
        score = target[1]
        search_image.delete()
        os.remove(image_path)
        print(score)
        if score>2:
            img = Image.objects.get(image_id= target_id)
            name = str(Image.get_image(img))
            dic = {"image-id": target_id, "name": name}
            logger.info(dic)
            return Response(dic)

        else:
            dic = "There is no matching image in this database"
            logger.info(dic)
            return Response(dic)

    else:
        logger.error(serializer.errors)
        return Response(serializer.errors)
        
    
@api_view(["POST"])
@permission_classes([AllowAny])
def Register_Users(request):
    try:
        logger.info(request.data)
        data = {}
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            account = serializer.save()
            account.is_active = False
            account.save()
            token = Token.objects.get_or_create(user=account)[0].key
            data["message"] = "user registered successfully"
            data["email"] = account.email
            data["username"] = account.username
            data["token"] = token
            current_site = get_current_site(request).domain
            relativeLink = reverse('email-verify')
            absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
            email_body = 'Hi '+account.username + \
            ' Use the link below to verify your email \n' + absurl
            data2 = {'email_body': email_body, 'to_email': account.email,
                'email_subject': 'Verify your email'}
            logger.info("Send email to activate account")
            send_mail(data2)

        else:
            data = serializer.errors
            logger.error(serializer.errors)

        return Response(data)
    
    except IntegrityError as e:
        account=User.objects.get(username='')
        account.delete()
        logger.error(str(e))
        raise ValidationError({"400": f'{str(e)}'})

    except KeyError as e:
        logger.error(str(e))
        raise ValidationError({"400": f'Field {str(e)} missing'})


@api_view(["POST"])
@permission_classes([AllowAny])
def login_user(request):
        logger.info(request.body)
        print(request.body)
        data = {}
        reqBody = json.loads(request.body)
        username = reqBody['username']
        print(username)
        password = reqBody['password']

        try:
            Account = User.objects.get(username=username)
        except BaseException as e:
            logger.error(str(e))
            raise ValidationError({"400": f'{str(e)}'})

        token = Token.objects.get_or_create(user=Account)[0].key
        print(token)
        if not check_password(password, Account.password):
            logger.error("Incorrect Login credentials")
            raise ValidationError({"message": "Incorrect Login credentials"})

        if Account:
            if Account.is_active:
                print(request.user)
                login(request, Account)
                data["message"] = "user logged in"
                data["email_address"] = Account.email

                Res = {"data": data, "token": token}

                return Response(Res)

            else:
                logger.error("Account not active")
                raise ValidationError({"400": f'Account not active'})

        else:
            logger.error("Account doesnt exist")
            raise ValidationError({"400": f'Account doesnt exist'})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def User_logout(request):
    request.user.auth_token.delete()
    logout(request)
    logger.info("User Logged out successfully")

    return Response('User Logged out successfully')


token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)
@api_view(["GET"])
@swagger_auto_schema(manual_parameters=[token_param_config])
def verifyEmail(request):
    token = request.GET.get('token')
    logger.info("received token : "+ str(token))
    print(token)
    token_obj = Token.objects.get(key=token)
    user = User.objects.get(id=token_obj.user_id)
    if not user.is_active:
        user.is_active = True
        user.save()
    logger.info("Email is activated")
    return Response({'email': 'Successfully activated'})


@api_view(["POST"])
def RequestPasswordReset(request):
    reqBody = json.loads(request.body)
    username = reqBody['username']
    user = User.objects.get(username=username)
    uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
    token = PasswordResetTokenGenerator().make_token(user)
    current_site = get_current_site(request=request).domain
    relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
    redirect_url = request.data.get('redirect_url', '')
    absurl = 'http://'+current_site + relativeLink
    email_body = 'Hello, \n Use link below to reset your password  \n' + \
                absurl+"?redirect_url="+redirect_url
    data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
    send_mail(data)
    return Response(data)


@api_view(["GET"])
def CheckRasswordToken(request, uidb64, token):
    redirect_url = request.GET.get('redirect_url')
    print(redirect_url)
    print(token)
    print(uidb64)
    try:
        id = smart_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(id=id)

        if not PasswordResetTokenGenerator().check_token(user, token):
            if len(redirect_url) > 3:
                # return CustomRedirect(redirect_url+'?token_valid=False')
                return Response(redirect_url+'?token_valid=False')
            else:
                # return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')
                return Response('FRONTEND_URL'+'?token_valid=False')

        if redirect_url and len(redirect_url) > 3:
            # return CustomRedirect(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
            return Response(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
        else:
            # return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')
            return Response('FRONTEND_URL'+'?token_valid=False')

    except DjangoUnicodeDecodeError as identifier:
            try:
                if not PasswordResetTokenGenerator().check_token(user):
                    # return CustomRedirect(redirect_url+'?token_valid=False')
                    return Response(redirect_url+'?token_valid=False')
                    
            except UnboundLocalError as e:
                return Response({'error': 'Token is not valid, please request a new one'})


@api_view(["POST"])
def SetNewPassword(request):
    logger.info(request.data)
    print(request)
    serializer = SetNewPasswordSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    message = {'success': True, 'message': 'Password reset success'}
    logger.info("password reset success")

    return Response(message)

   
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def getAllImage(request):
    logger.info(request.data)
    token = request.user.auth_token
    user_id = token.user_id
    try:
        images = Image.objects.filter(user_id=user_id)
        serializer = ImageSerializer(images, many=True)
        return Response(serializer.data)

    except BaseException as e:
        logger.error(str(e))
        raise ValidationError({"400": f'{str(e)}'})


@api_view(["GET"])
@permission_classes([AllowAny])
def test_Email(request):
    try:
        logger.info(request.data)
        logger.info("hello")
        email_body = 'Hi '+"malith" + \
            ' Use the link below to verify your email \n'
        data2 = {'email_body': email_body, 'to_email': "malithattanayaka99@gmail.com",
                'email_subject': 'Verify your email'}
        logger.info("Send email to activate account")
        send_mail(data2)

        data = {"msg":"verify"}
        return Response(data)
    
    except IntegrityError as e:
        account=User.objects.get(username='')
        account.delete()
        logger.error(str(e))
        raise ValidationError({"400": f'{str(e)}'})

    except KeyError as e:
        logger.error(str(e))
        raise ValidationError({"400": f'Field {str(e)} missing'})
