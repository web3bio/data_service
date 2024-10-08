#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 18:54:06
LastEditors: Zella Zhong
LastEditTime: 2024-10-06 19:01:38
FilePath: /data_service/src/model/ensname.py
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


class EnsnameModel(Base):
    """EnsnameModel"""
    __tablename__ = "ensname"
    id: int = Column(Integer, primary_key=True, index=True)
    namenode: str = Column(String, unique=True, index=True)
    name: str = Column(String, index=True, nullable=True)
    label_name: str = Column(String, index=True, nullable=True)
    label: str = Column(String, nullable=True)
    erc721_token_id: str = Column(String, nullable=True)
    erc1155_token_id: str = Column(String, nullable=True)
    parent_node: str = Column(String, nullable=True)

    registration_time: DateTime = Column(DateTime, nullable=True)
    registered_height: int = Column(Integer, nullable=True)
    registered_hash: str = Column(String, nullable=True)

    expire_time: DateTime = Column(DateTime, nullable=True)
    is_migrated: bool = Column(Boolean)
    is_wrapped: bool = Column(Boolean)
    wrapped_owner: str = Column(String, index=True, nullable=True)

    resolver: str = Column(String, nullable=True)
    owner: str = Column(String, index=True, nullable=True)
    resolved_address: str = Column(String, index=True, nullable=True)
    reverse_address: str = Column(String, index=True, nullable=True)
    is_primary: bool = Column(Boolean)

    contenthash: str = Column(String, nullable=True)
    texts: dict = Column(JSON, nullable=True)
    resolved_records: dict = Column(JSON, nullable=True)
