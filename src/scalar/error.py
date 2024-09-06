#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-29 17:05:41
LastEditors: Zella Zhong
LastEditTime: 2024-08-29 17:55:21
FilePath: /data_service/src/scalar/error.py
Description: 
'''
import strawberry
from strawberry.extensions import MaskErrors
from graphql.error import GraphQLError

class VisibleError(Exception):
    pass

class PlatformNotSupport(Exception):
    def __init__(self, platform):
        self.message = "[" + platform + "]" + " platform is not supported"

class DomainInvalid(Exception):
    def __init__(self, name):
        self.message = "Given name is invalid " + "[" + name + "]"

class DomainNotFound(Exception):
    def __init__(self, name):
        self.message = "Couldn't find domain by given name " + "[" + name + "]"

class EvmAddressInvalid(Exception):
    def __init__(self, addr):
        self.message = "Given evm address is invalid " + "[" + addr + "]"


def should_mask_error(error: GraphQLError) -> bool:
    original_error = error.original_error
    if original_error and isinstance(original_error, VisibleError):
        return False
    if original_error and isinstance(original_error, PlatformNotSupport):
        return False
    if original_error and isinstance(original_error, DomainInvalid):
        return False
    if original_error and isinstance(original_error, DomainNotFound):
        return False
    if original_error and isinstance(original_error, EvmAddressInvalid):
        return False

    return True
