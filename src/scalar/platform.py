#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 17:45:51
LastEditors: Zella Zhong
LastEditTime: 2024-10-24 17:34:34
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
    sns = "sns"
    farcaster = "farcaster"
    lens = "lens"
    clusters = "clusters"
    basenames = "basenames"
    unstoppabledomains = "unstoppabledomains"
    space_id = "space_id"
    dotbit = "dotbit"

    bitcoin = "bitcoin"
    litecoin = "litecoin"
    dogecoin = "dogecoin"
    aptos = "aptos"
    stacks = "stacks"
    tron = "tron"
    ton = "ton"
    xrpc = "xrpc"
    cosmos = "cosmos"
