#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-29 23:16:15
LastEditors: Zella Zhong
LastEditTime: 2024-08-30 00:17:31
FilePath: /data_service/src/scalar/common.py
Description: 
'''
import strawberry
from strawberry.scalars import Union
from datetime import datetime, timezone

# Define your custom scalar
EpochDateTime = strawberry.scalar(
    datetime,
    name="datetime",
    description="epoch datetime",
    serialize=lambda value: int(value.timestamp()),
    parse_value=lambda value: datetime.fromtimestamp(int(value), timezone.utc),
)


# This is needed because GraphQL does not support 64 bit integers
BigInt = strawberry.scalar(
    Union[int, str],  # type: ignore
    serialize=lambda v: int(v),
    parse_value=lambda v: str(v),
    description="BigInt field",
)