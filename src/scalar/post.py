#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-28 21:43:35
LastEditors: Zella Zhong
LastEditTime: 2024-08-29 01:49:10
FilePath: /cryptodata_apollographql/src/scalar/post.py
Description: 
'''
import strawberry

from datetime import datetime
from pydantic import Field, typing

@strawberry.type
class Post:
    id: int
    title: typing.Optional[str] = ""
    description: typing.Optional[str] = ""
    created_at : typing.Optional[int] = None
    # created_at : typing.Optional[datetime] = Field(default_factory=datetime.now)

@strawberry.type
class PostNotFound:
    message: str = "Couldn't find Posts by given id"


UpdatePostResponse = strawberry.union("UpdatePostResponse", \
                                       (Post, PostNotFound))
