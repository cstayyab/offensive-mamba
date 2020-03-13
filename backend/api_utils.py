"""
Contains Helper class(es) used by RESTful API and Database Handler
"""
import re
import hashlib
import json
from flask import make_response
from jwt import (
    JWT,
    jwk_from_pem
)
from cryptography.fernet import Fernet

# Key For Encrypting Passwords
PASSKEY = b'0eg3rEFlskSVGNUX2gKTfQ2Q6iZ1Qp5NkbmvAJEVHu4='

class APIUtils:
    """
    Contains helper functions needed for RESTful API and DatabaseHandler
    """
    firstname_regex = r"^[^±!@£$%^&*_+§¡€#¢§¶•ªº«\\/<>?:;|=.,\}\{\[\]}]{2,20}$"
    lastname_regex = r"^[^±!@£$%^&*_+§¡€#¢§¶•ªº«\\/<>?:;|=.,\}\{\[\]]{2,20}$"
    email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})"
    username_regex = r"^[a-zA-Z0-9_.]{4,32}"
    companyname_regex = r"^[^±!@£$%^&*_+§¡€#¢§¶•ªº«\\/<>?:;|=.,\}\{\[\]]{2,64}$"
    valid_code_for_choices = ("verifyEmail", "resetPassword")
    ipaddress_regex = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    @staticmethod
    def validate(key: str, value: str) -> bool:
        validators = {
            "firstname": APIUtils.firstname_regex,
            "lastname": APIUtils.lastname_regex,
            "email": APIUtils.email_regex,
            "username":APIUtils.username_regex,
            "password": APIUtils.password_regex,
            "companyname": APIUtils.companyname_regex,
            "ipaddress": APIUtils.ipaddress_regex
        }
        if key in validators.keys():
            return re.match(validators[key], value) is not None
        else:
            raise ValueError("Invalid value for key. Valid values are " + str(validators.keys()))

    @staticmethod
    def generatePasswordHash(password: str) -> str:
        return hashlib.md5(password.encode('utf-8')).hexdigest()
    
    @staticmethod
    def encrypt_password(password: str) -> str:
        return Fernet(PASSKEY).encrypt(bytes(password, 'utf-8')).decode('utf-8')
    
    @staticmethod
    def decrypt_password(encrypted_password: str) -> str:
        return Fernet(PASSKEY).decrypt(bytes(encrypted_password, 'utf-8')).decode('utf-8')

    @staticmethod
    def output_json(data, code, headers=None):
        content_type = 'application/json'
        dumped = json.dumps(data)
        if headers:
            headers.update({'Content-Type': content_type})
        else:
            headers = {'Content-Type': content_type}
        response = make_response(dumped, code, headers)
        return response

    @staticmethod
    def encrypt_jwt_token(data):
        with open('private.pem', 'rb') as fhandle:
            signing_key = jwk_from_pem(fhandle.read())
        return JWT().encode(data, signing_key, 'RS256')

    @staticmethod
    def decrypt_jwt_token(token):
        with open('private.pem', 'rb') as fhandle:
            verifying_key = jwk_from_pem(fhandle.read())
            return JWT().decode(token, verifying_key)
