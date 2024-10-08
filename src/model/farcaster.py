#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 23:03:44
LastEditors: Zella Zhong
LastEditTime: 2024-10-07 01:37:42
FilePath: /data_service/src/model/farcaster.py
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

class FarcasterProfile(Base):
    """FarcasterProfile"""
    __tablename__ = "farcaster_profile"
    id: int = Column(Integer, primary_key=True, index=True)
    fid: int = Column(Integer, unique=True, index=True)
    fname: str = Column(String, index=True, nullable=True)
    label_name: str = Column(String, index=True, nullable=True)

    avatar: str = Column(String, nullable=True)
    display_name: str = Column(String, nullable=True)
    description: str = Column(String, nullable=True)
    cover_picture: str = Column(String, nullable=True)
    custody_address: str = Column(String, nullable=True)

    network: str = Column(String, index=True, nullable=True)
    address: str = Column(String, index=True, nullable=True)

    texts: dict = Column(JSON, nullable=True)
    registration_time: DateTime = Column(DateTime, nullable=True)
    delete_time: DateTime = Column(DateTime, nullable=True)


class FarcasterVerified(Base):
    """FarcasterVerified"""
    __tablename__ = "farcaster_verified_address"
    id: int = Column(Integer, primary_key=True, index=True)
    fid: int = Column(Integer, unique=True, index=True)
    fname: str = Column(String, nullable=True)
    network: str = Column(String, nullable=True)
    address: str = Column(String, unique=True, index=True)


class FarcasterSocial(Base):
    """FarcasterSocial"""
    __tablename__ = "farcaster_social"
    fid: int = Column(Integer, primary_key=True, unique=True, index=True)
    follower: int = Column(Integer, nullable=False)
    following: int = Column(Integer, nullable=False)
    update_time: DateTime = Column(DateTime, nullable=True)