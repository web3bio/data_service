#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 17:35:11
LastEditors: Zella Zhong
LastEditTime: 2024-10-12 15:38:23
FilePath: /data_service/src/scalar/identity_connection.py
Description: 
'''
import strawberry
from enum import Enum

# from .data_source import DataSource
from .platform import Platform

@strawberry.enum
class EdgeType(Enum):
    Auth = "Auth"
    Proof = "Proof"
    Hold = "Hold"
    Resolve = "Resolve"
    Reverse_Resolve = "Reverse_Resolve"

@strawberry.type
class IdentityConnection:
    edge_type: EdgeType
    data_source: Platform
    source: str
    target: str