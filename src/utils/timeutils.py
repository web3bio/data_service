#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-25 00:24:48
LastEditors: Zella Zhong
LastEditTime: 2024-10-25 00:24:50
FilePath: /data_service/src/utils/timeutils.py
Description: 
'''
import time
from datetime import datetime

# Helper to get current Unix time in microseconds (for unique_value)
def get_unix_microseconds():
    current_time_seconds = time.time()
    microseconds = int(current_time_seconds * 1e6)  # Multiply by 1e6 to get microseconds
    return microseconds

# Helper to get the current time in "yyyy-mm-dd HH:MM:SS" format
def get_current_time_string():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Helper to parse the 'updated_at' string into a datetime object
def parse_time_string(time_str):
    return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")