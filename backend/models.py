"""
Module defining MongoEngine Models
"""
from datetime import datetime
from mongoengine import (
    Document,
    StringField,
    IntField,
    EmailField,
    BooleanField,
    ReferenceField,
    DictField,
    DateTimeField,
    UUIDField,
    ListField
)
from api_utils import APIUtils

class User(Document):
    firstName = StringField(regex=APIUtils.firstname_regex, required=True)
    lastName = StringField(regex=APIUtils.lastname_regex, required=True)
    companyName = StringField(regex=APIUtils.companyname_regex, required=True)
    username = StringField(regex=APIUtils.username_regex, required=True, unique=True)
    emailAddress = EmailField(required=True, unique=True)
    password = StringField(required=True)
    recoveryCode = IntField(min_value=100000, max_value=999999, required=False, null=True)
    codeFor = StringField(null=True, choices=APIUtils.valid_code_for_choices, required=False)
    publicIP = StringField(regex=APIUtils.ipaddress_regex, required=False, default=None, null=True)
    emailVerified = BooleanField(required=True, default=False)
    verifiedPublicIP = BooleanField(required=True, default=False)
    publicIPVerifier = UUIDField(required=False, default=None, null=True, binary=False)

class LocalSystem(Document):
    userId = ReferenceField(User, required=True)
    os = StringField(required=True, null=True, default=None, sparse=True)
    localIP = StringField(regex=APIUtils.ipaddress_regex, required=True)
    systemUp = BooleanField(required=True)
    openPorts = DictField(required=False, default=dict(), sparse=True, null=True)
    closedPorts = ListField(required=False, default=list(), sparse=True, null=True)
    lastScanTime = DateTimeField(required=False, default=None, null=True)

class ScanningEvent(Document):
    systemId = ReferenceField(LocalSystem, required=True)
    scanTime = DateTimeField(required=True, default=datetime.now())
    systemUp = BooleanField(required=True, default=True)
    openPorts = DictField(required=False, default=dict(), sparse=True, null=True)
    closedPorts = ListField(required=False, default=list(), sparse=True, null=True)
    

class ExploitingEvent(Document):
    systemId = ReferenceField(LocalSystem, required=True)
    scanId = ReferenceField(ScanningEvent, required=True)
    timestamp = DateTimeField(required=True, default=datetime.now())
    exploitedUsing = StringField(required=True, choices=['Metasploit'])
    success = BooleanField(required=True, default=False)
    exploit = StringField(required=True)
    payload = StringField(required=True)
    port = IntField(required=True)
    # vulnName = StringField(required=True)
    # vulnDescription = StringField(required=True)
    # sessionType = StringField(reuired=True)

class PostExploitationEvent(Document):
    exploitationId = ReferenceField(ExploitingEvent, required=True)
