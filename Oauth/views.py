from rest_framework.permissions import IsAuthenticated,IsAdminUser,AllowAny
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode 
from rest_framework.decorators import api_view,permission_classes
from rest_framework.authentication import TokenAuthentication
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth import login, authenticate,logout
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.hashers import check_password
from django.contrib.auth.hashers import make_password
from django.template.loader import render_to_string  
from django.core.exceptions import ValidationError
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model
from .tokens import account_activation_token
from rest_framework.response import Response
from django.core.mail import EmailMessage
from rest_framework.views import APIView
from django.http import HttpResponse
from django.shortcuts import render
from rest_framework import status
from .models import CustomUser
from .serializer import *
import json

class Register(APIView):
    authentication_classes = ([])
    permission_classes = ([AllowAny])
    def post(self,request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = CustomUser()
            username         = ''.join(str(request.data['username']))    
            first_name       = ''.join(str(request.data['first_name']))
            last_name        = ''.join(str(request.data['last_name']))  
            email            = ''.join(str(request.data['email']))          
            password         = ''.join(str(make_password(request.data['password'])))    
            profile_pic      = ''.join(str(request.data['profile_pic']))
            own_pc           = ''.join(str(request.data['own_pc']))
            sub_to_newsletter= ''.join(str(request.data['sub_to_newsletter']))
            user.username    = username    
            user.first_name  = first_name  
            user.last_name   = last_name   
            user.email       = email       
            user.password    = password    
            user.profile_pic = profile_pic

            if sub_to_newsletter == 'true':  
                user.sub_to_newsletter = True
            elif sub_to_newsletter == 'false':
                user.sub_to_newsletter = False
            if own_pc == 'true':
                user.own_pc = True
            elif own_pc == 'true':
                user.own_pc = False
            
            account = serializer.save()
            user = CustomUser.objects.get(pk=account.id)
            print(user)
            activateEmail(request,user)
            token = Token.objects.get(user=account).key
            return Response({
                "response":"User Created Successfully",
                "token": {token},
                },status=status.HTTP_201_CREATED)
        return Response({'error':serializer.errors}, status.HTTP_400_BAD_REQUEST)


class GetUserInfo(APIView):
    authentication_classes = ([])
    permission_classes = ([AllowAny])
    def post(self,request):  
        try:
            token = Token.objects.get(key=request.data['token'])
            user = token.user
            
        except:
            return Response({'error':'Invalid token.'})
        user_filter  = CustomUser.objects.filter(email=user)
        serializer   = FindUserSerializer(user_filter,many=True)
        return Response({
            'data' : serializer.data,
            'token':str(token)
            })

class GetAllUsers(APIView):
    authentication_classes = ([])
    permission_classes = ([])
    def get(self,request):
        try:
            token = Token.objects.get(key=request.data['token'])
            user = token.user
        except:
            return Response({'error':'Invalid token.'})
        user = CustomUser.objects.get(email=user)
        print(user)
        if user.is_admin == True:    
            users      = CustomUser.objects.all()
            serializer = AllUsersSerializer(users,many = True)
            return Response(serializer.data)
        return Response({'error':"You Don't Have Permissions."})


#doesn't work yet (have bugs)
class UpdateUserInfo(APIView):
    authentication_classes = ([TokenAuthentication])
    permission_classes = ([IsAuthenticated])
    def put(self,request):
        try:
            token = Token.objects.get(key=request.data['token'])
            user_info = token.user
        except CustomUser.DoesNotExist:
            return Response({'error':"User Not Fount"})
        serializer = UserSerializer(user_info,data=request.data)
        if serializer.is_valid():
            user = CustomUser()
            own_pc           = ''.join(str(request.data['own_pc']))
            sub_to_newsletter= ''.join(str(request.data['sub_to_newsletter']))
            user.username    = ''.join(str(request.data['username']))   
            user.first_name  = ''.join(str(request.data['first_name'])) 
            user.last_name   = ''.join(str(request.data['last_name']))    
            user.email       = ''.join(str(request.data['email']))       
            user.password    = ''.join(str(make_password(request.data['password'])))
            if sub_to_newsletter == 'true':  
                user.sub_to_newsletter = True
            elif sub_to_newsletter == 'false':
                user.sub_to_newsletter = False
            if own_pc == 'true':
                user.own_pc = True
            elif own_pc == 'true':
                user.own_pc = False
            user.save()
            user_data = {
            }
            user_data['response']          = 'User Updated Successfully.'
            user_data['username']          = user.username
            user_data['first_name']        = user.first_name
            user_data['last_name']         = user.last_name
            user_data['email']             = user.email
            user_data['password']          = user.password
            user_data['own_pc']            = own_pc
            user_data['sub_to_newsletter'] = sub_to_newsletter
            return Response(
                {"User Data":user_data,"token":token},
                status=status.HTTP_201_CREATED
                    )
        return Response({"error":serializer.errors},status=status.HTTP_400_BAD_REQUEST)


class DeleteUserInfo(APIView):
    authentication_classes = ([])
    permission_classes = ([AllowAny])
    def delete(self,request):
        try:
            token = Token.objects.get(key=request.data['token'])
            user_info = token.user
            user_info = CustomUser.objects.get(email=user_info)
        except CustomUser.DoesNotExist:
            return Response({'error':"User Not Fount"})
        user_info.delete()
        token.delete()
        return Response({'response':"User Deleted"})


class Login(APIView):
    authentication_classes = ([])
    permission_classes = ([AllowAny])
    def post(self,request_var):
        data = {}
        reqBody = json.loads(request_var.body)
        email1 = reqBody['email']
        print(email1)
        password = reqBody['password']
        try:
            Account = CustomUser.objects.get(email=email1)
        except BaseException as e:
            return Response({"400": f'{str(e)}'})
        token = Token.objects.get_or_create(user=Account)[0].key
        if not check_password(password, Account.password):
            return Response({"response": "Incorrect Login credentials"})
        if Account:
            if Account.is_active:
                print(request_var.user)
                login(request_var, user=Account)
                data["response"] = "user logged in"
                data["email"] = Account.email
                Res = {"data": data, "token": token}
                return Response(Res)
            else:
                raise Response({"400": f'Account is not active'})
        else:
            raise Response({"400": f'Account doesnt exist'})

class Logout(APIView):
    authentication_classes = ([])
    permission_classes = ([AllowAny])
    def post(self,request):
        try:
            Token.objects.filter(key=request.data['token']).delete()
        except (AttributeError):
            return Response({"Error": "Error"},status=status.HTTP_200_OK)

        logout(request)

        return Response({"success": ("Successfully logged out.")},status=status.HTTP_200_OK)


def activateEmail(request, token_data):
    mail_subject = 'Activate your user account.'
    message = render_to_string('Oauth/acc_active_email.html', {
        'user': token_data.username,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(token_data.id)),
        'token': account_activation_token.make_token(token_data),
        'protocol': 'https' if request.is_secure() else 'http'
    })
    to_email = token_data.email
    email = EmailMessage(mail_subject, message, to=[to_email])
    email.content_subtype = 'html'
    if email.send():
        Response(f'Sent Email.')
    else:
        Response(f'Problem sending confirmation email to {to_email}, check if you typed it correctly.')

def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.active = True
        user.save()
        return render(request,'Oauth/email_confirmed.html', {'first_name':str(user.first_name).capitalize()})
    else:
        return render(request,'Oauth/email_confirmed.html', {'error':'Activation Link Is Invalid'})