#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-24 23:30:28
LastEditors: Zella Zhong
LastEditTime: 2024-10-25 01:42:16
FilePath: /data_service/src/scalar/type_convert.py
Description: 
'''
import json
import logging
import strawberry

from enum import Enum
from datetime import datetime, timedelta

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value  # Serialize Enums to their value
        elif isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif hasattr(obj, "__dict__"):  # Serialize datetime to "yyyy-mm-dd HH:MM:SS" format
            return obj.__dict__
        return super().default(obj)


def strawberry_type_to_jsonstr(input_obj):
    if input_obj is None:
        return json.dumps({})
    obj_dict = strawberry.asdict(input_obj)
    json_str = json.dumps(obj_dict, cls=CustomJSONEncoder)
    return json_str
