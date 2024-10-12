#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-12 14:05:11
LastEditors: Zella Zhong
LastEditTime: 2024-10-12 14:09:05
FilePath: /data_service/src/model/clusters.py
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

class ClustersProfile(Base):
    """ClustersProfile"""
    __tablename__ = "clusters_profile"
    id: int = Column(Integer, primary_key=True, index=True)
    cluster_id: int = Column(Integer, index=True)
    bytes32_address: str = Column(String, nullable=True)
    network: str = Column(String, nullable=True)
    address: str = Column(String, index=True, nullable=False)
    address_type: str = Column(String, index=True, nullable=False)
    is_verified: bool = Column(Boolean)

    cluster_name: str = Column(String, index=True, nullable=False)
    name: str = Column(String, index=True, nullable=True)
    avatar: str = Column(String, nullable=True)
    display_name: str = Column(String, nullable=True)
    description: str = Column(String, nullable=True)
    
    texts: dict = Column(JSON, nullable=True)
    registration_time: DateTime = Column(DateTime, nullable=True)
    create_time: DateTime = Column(DateTime, nullable=True)
    update_time: DateTime = Column(DateTime, nullable=True)
    delete_time: DateTime = Column(DateTime, nullable=True)
