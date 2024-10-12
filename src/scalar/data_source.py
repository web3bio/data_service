#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 17:36:16
LastEditors: Zella Zhong
LastEditTime: 2024-10-12 15:38:03
FilePath: /data_service/src/scalar/data_source.py
Description: 
'''
import strawberry
from enum import Enum

@strawberry.enum
class DataSource(Enum):
    farcaster = "farcaster"
    lens = "lens"
    ens = "ens"
    clusters = "clusters"