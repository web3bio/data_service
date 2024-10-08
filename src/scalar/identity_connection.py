#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 17:35:11
LastEditors: Zella Zhong
LastEditTime: 2024-10-07 04:10:21
FilePath: /data_service/src/scalar/identity_connection.py
Description: 
'''
import strawberry
from enum import Enum

from .data_source import DataSource

@strawberry.enum
class EdgeType(Enum):
    Hold = "Hold"
    Resolve = "Resolve"
    Reverse_Resolve = "Reverse_Resolve"

@strawberry.type
class IdentityConnection:
    edge_type: EdgeType
    data_source: DataSource
    source: str
    target: str