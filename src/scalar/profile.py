#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 17:39:33
LastEditors: Zella Zhong
LastEditTime: 2024-10-07 03:09:36
FilePath: /data_service/src/scalar/profile.py
Description: 
'''
import strawberry

from datetime import datetime, timedelta
from pydantic import Field, typing
from strawberry.scalars import JSON


from .platform import Platform
from .network import Network

@strawberry.type
class SocialProfile:
    uid: str = ""
    following: typing.Optional[int] = 0
    follower: typing.Optional[int] = 0
    update_at: typing.Optional[datetime] = None


@strawberry.type
class Profile:
    uid: typing.Optional[str] = None
    identity: str = ""
    platform: Platform
    network: typing.Optional[Network] = None
    address: typing.Optional[str] = None
    display_name: typing.Optional[str] = None
    avatar: typing.Optional[str] = None
    cover_picture: typing.Optional[str] = None
    description: typing.Optional[str] = None
    contenthash: typing.Optional[str] = None
    texts: typing.Optional[JSON] = None
    records: typing.Optional[JSON] = None
    social: typing.Optional[SocialProfile] = None