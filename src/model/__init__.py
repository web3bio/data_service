#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-28 21:15:34
LastEditors: Zella Zhong
LastEditTime: 2024-10-06 19:02:39
FilePath: /data_service/src/model/__init__.py
Description: 
'''
from sqlalchemy.ext.declarative import declarative_base

from datetime import datetime
from sqlalchemy import DateTime, BigInteger
from sqlalchemy.types import TypeDecorator

# declarative_base() is a factory function that constructs a base class
# for declarative class definitions (which is assigned to the Base variable in model).
Base = declarative_base()

from .post import Post
from .basename import BasenameModel
from .ensname import EnsnameModel


class UnixToDatetime(TypeDecorator):
    # convert unix timestamp to datetime object
    impl = BigInteger

    # convert datetime object to unix timestamp when inserting data to database
    def process_bind_param(self, value, dialect=None):
        if value is not None:
            return int(value.timestamp())
        else:
            return None

    def process_result_value(self, value, dialect=None):
        return datetime.fromtimestamp(value)