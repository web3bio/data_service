#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-28 21:32:19
LastEditors: Zella Zhong
LastEditTime: 2024-10-24 21:42:46
FilePath: /data_service/src/utils/utils.py
Description: 
'''
import re
import copy
import logging
from sqlalchemy.inspection import inspect
from eth_utils import encode_hex, keccak, is_address


def convert_camel_case(name):
    pattern = re.compile(r'(?<!^)(?=[A-Z])')
    name = pattern.sub('_', name).lower()
    return name

def get_only_selected_fields(db_baseclass_name, info):
    attr_names = [c_attr.key for c_attr in inspect(db_baseclass_name).mapper.column_attrs]
    selected_fields = [convert_camel_case(field.name) for field in info.selected_fields[0].selections]
    filter_selected_fields = list(set(attr_names) & set(selected_fields))
    # print("attr_names", attr_names)
    # print("selected_fields", selected_fields)
    # print("filter_selected_fields", filter_selected_fields)
    selected_fields = [getattr(db_baseclass_name, f) for f in filter_selected_fields]
    return selected_fields

def check_valid_data(model_data_object, model_class):
    data_dict = {}
    for column in model_class.__table__.columns:
        try:
            data_dict[column.name] = getattr(model_data_object,column.name)
        except:
            pass
    return data_dict

def compute_namehash_nowrapped(name):
    node = b'\x00' * 32  # 32 bytes of zeroes (initial nodehash for the root)
    self_node = ""
    items = name.split('.')
    for item in reversed(items):
        label_hash = keccak(item.encode('utf-8'))
        node = keccak(node + label_hash)  # keccak256 of node + label_hash
        self_node = node

    return encode_hex(self_node)


def bytes32_to_uint256(value):
    '''
    description: bytes32_to_uint256
    param: value bytes32 
    return: id uint256(str)
    '''
    # Remove the '0x' prefix if it exists and convert the hex string to an integer
    trim_value = value.lstrip('0x')
    # Convert the bytes32 address back to a uint256 integer
    return str(int(trim_value, 16))


def uint256_to_bytes32(value):
    '''
    description: uint256_to_bytes32
    param: value uint256(str)
    return: bytes32 address(0x64)
    '''
    # token ID uint256
    # bytes32 address
    # Convert the integer to a 64-character hexadecimal string (32 bytes)
    if value is None:
        return '0x'
    int_value = int(value)
    return '0x' + format(int_value, '064x')


def check_evm_address(addr):
    if is_address(addr):
        return True

    return False
    