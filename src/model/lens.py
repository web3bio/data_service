#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-07 01:32:07
LastEditors: Zella Zhong
LastEditTime: 2024-10-25 23:15:31
FilePath: /data_service/src/model/lens.py
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

class LensV2Profile(Base):
    """LensV2 profile"""
    __tablename__ = "lensv2_profile"
    profile_id: int = Column(Integer, primary_key=True, unique=True, index=True)
    profile_id_hex: str = Column(String, nullable=True)
    name: str = Column(String, index=True, nullable=True)
    handle_name: str = Column(String, index=True, nullable=True)
    namespace: str = Column(String, nullable=True)
    label_name: str = Column(String, index=True, nullable=True)
    is_primary: bool = Column(Boolean)

    # handle_node_id: str = Column(String, nullable=True)
    # handle_token_id: str = Column(String, nullable=True)

    avatar: str = Column(String, nullable=True)
    display_name: str = Column(String, nullable=True)
    description: str = Column(String, nullable=True)
    cover_picture: str = Column(String, nullable=True)

    tx_hash: str = Column(String, nullable=True)
    network: str = Column(String, nullable=True)
    address: str = Column(String, index=True, nullable=True)
    update_time: DateTime = Column(DateTime, nullable=True)

    texts: dict = Column(JSON, nullable=True)
    registration_time: DateTime = Column(DateTime, nullable=True)

class LensV2Social(Base):
    """LensV2 social"""
    __tablename__ = "lensv2_social"
    profile_id: int = Column(Integer, primary_key=True, unique=True, index=True)
    follower: int = Column(Integer, nullable=False)
    following: int = Column(Integer, nullable=False)
    update_time: DateTime = Column(DateTime, nullable=True)
