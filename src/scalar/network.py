#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 17:23:57
LastEditors: Zella Zhong
LastEditTime: 2024-10-06 20:45:05
FilePath: /data_service/src/scalar/network.py
Description: 
'''
import strawberry
from enum import Enum

@strawberry.enum
class Network(Enum):
    ethereum = "ethereum"
    base = "base"
    solana = "solana"

@strawberry.type
class Address:
    network: Network
    address: str