from django.shortcuts import render
from Computerizer.settings import MAILCHIMP_API_KEY, MAILCHIMP_LIST_ID
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from mailchimp_marketing import Client
from mailchimp_marketing.api_client import ApiClientError

class SubscribeMailchimp(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        email = request.data['email']
        firstName = request.data['firstName']
        lastName = request.data['lastName']

        mailchimpClient = Client()
        mailchimpClient.set_config({
            "api_key": MAILCHIMP_API_KEY,
        })

        userInfo = {
            "email_address": email,
            "status": "subscribed",
            "merge_fields": {
                "FNAME": firstName,
                "LNAME": lastName
            }
        }

        try:
            mailchimpClient.lists.add_list_member(MAILCHIMP_LIST_ID, userInfo)
            return Response("success")
        except ApiClientError as error:
            return Response(error.text)