#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 17:45:51
LastEditors: Zella Zhong
LastEditTime: 2024-10-21 15:33:12
FilePath: /data_service/src/scalar/platform.py
Description: 
'''
import strawberry
from enum import Enum

@strawberry.enum
class Platform(Enum):
    ethereum = "ethereum"
    solana = "solana"
    ens = "ens"
    farcaster = "farcaster"
    lens = "lens"
    clusters = "clusters"
    basenames = "basenames"

    bitcoin = "bitcoin"
    litecoin = "litecoin"
    dogecoin = "dogecoin"
    aptos = "aptos"
    stacks = "stacks"
    tron = "tron"
    ton = "ton"
    xrpc = "xrpc"
    cosmos = "cosmos"
