from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from rest_framework.validators import UniqueValidator
from rest_framework.exceptions import AuthenticationFailed
from .models import Image, TemporaryImage



class ImageSerializer(serializers.ModelSerializer):
	class Meta:
		model = Image
		fields ='__all__'
		

class TemporarySerializer(serializers.ModelSerializer):
	class Meta:
		model = TemporaryImage
		fields ='__all__'


# Register Serializer
class RegisterSerializer(serializers.ModelSerializer):
	email = serializers.EmailField(required=True, validators=[UniqueValidator(queryset=User.objects.all())])
	username = serializers.CharField(required=True, validators=[UniqueValidator(queryset=User.objects.all())])
	class Meta:
		model = User
		fields = ('username', 'email', 'password')
		extra_kwargs = {'password': {'write_only': True}}

	def create(self, validated_data):
		user = User.objects.create_user(validated_data['username'], validated_data['email'], validated_data['password'])

		return user

class SetNewPasswordSerializer(serializers.Serializer):
	password = serializers.CharField(write_only=True)
	token = serializers.CharField(write_only=True)
	uidb64 = serializers.CharField(write_only=True)

	class Meta:
		fields = ['password', 'token', 'uidb64']

	def validate(self, attrs):
		try:
			password = attrs.get('password')
			token = attrs.get('token')
			uidb64 = attrs.get('uidb64')

			id = force_str(urlsafe_base64_decode(uidb64))
			print(id, "##",token,"$$$$",password)
			user = User.objects.get(id=id)
			if not PasswordResetTokenGenerator().check_token(user, token):
				raise AuthenticationFailed('The reset link is invalid', 401)
			print("hello")
			user.set_password(password)
			print("aaaaaaaaaa")
			user.save()
			print("bbbbbbbbb")
			return (user)
		except Exception as e:
			raise AuthenticationFailed('The reset link is invalid', 401)
