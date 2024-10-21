#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-29 02:00:40
LastEditors: Zella Zhong
LastEditTime: 2024-10-21 14:41:55
FilePath: /data_service/src/model/basename.py
Description: 
'''
import time
import logging
from datetime import datetime
from sqlalchemy import Column, Boolean, Integer, String, ForeignKey, DateTime, BigInteger, JSON
from pydantic.color import Optional
from pydantic import typing
from sqlalchemy.types import TypeDecorator
from urllib.parse import unquote

from . import Base


class DatetimeToTimestamp(TypeDecorator):
    # convert unix timestamp to datetime object
    impl = DateTime

    # convert datetime object to unix timestamp when inserting data to database
    def process_bind_param(self, value, dialect=None):
        return datetime.fromtimestamp(value)

    def process_result_value(self, value, dialect=None):
        if value is not None:
            unix_timestamp = int(value.timestamp())
            if unix_timestamp <= 0:
                return None
            return unix_timestamp
        else:
            return None

class BasenameModel(Base):
    """Post"""
    __tablename__ = "basenames"
    id: int = Column(Integer, primary_key=True, index=True)
    namenode: str = Column(String, unique=True, index=True)
    name: str = Column(String, index=True, nullable=True)
    label_name: str = Column(String, index=True, nullable=True)
    label: str = Column(String, nullable=True)
    erc721_token_id: str = Column(String, nullable=True)
    parent_node: str = Column(String, nullable=True)

    registration_time: DateTime = Column(DateTime, nullable=True)
    registered_height: int = Column(Integer, nullable=True)
    registered_hash: str = Column(String, nullable=True)

    expire_time: DateTime = Column(DateTime, nullable=True)
    grace_period_ends: DateTime = Column(DateTime, nullable=False)

    owner: str = Column(String, index=True, nullable=True)
    resolver: str = Column(String, nullable=True)
    resolved_address: str = Column(String, index=True, nullable=True)
    reverse_address: str = Column(String, index=True, nullable=True)
    is_primary: bool = Column(Boolean)

    contenthash: str = Column(String, nullable=True)
    update_time: DateTime = Column(DateTime, nullable=False)
    texts: dict = Column(JSON, nullable=True)
    resolved_records: dict = Column(JSON, nullable=True)
