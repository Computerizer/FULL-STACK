from rest_framework import serializers
from rest_framework.response import Response
from .models import CustomUser
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id','username','first_name','last_name','email','password','sub_to_newsletter','own_pc','is_active')
    def update(self, instance, validated_data):
        instance.is_active = validated_data.get('is_active', instance.is_active)
        instance.save()
        return instance
    
    
class FindUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('__all__')
class AllUsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('__all__')

class LoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields=('email','password')

class ActivateUserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = CustomUser
        fields = ('id','username','first_name','last_name','email','password','sub_to_newsletter','own_pc','is_active')
    def save(self,*args,**kwargs):
        super().save(*args, **kwargs)