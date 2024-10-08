#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 18:21:28
LastEditors: Zella Zhong
LastEditTime: 2024-10-07 03:31:14
FilePath: /data_service/src/scalar/identity_graph.py
Description: 
'''
import strawberry

from datetime import datetime, timedelta
from pydantic import Field, typing
from strawberry.scalars import JSON

from .network import Network, Address
from .platform import Platform
from .profile import Profile
from .identity_connection import IdentityConnection, EdgeType
from .data_source import DataSource

@strawberry.type
class IdentityRecordSimplified:
    id: str = ""
    identity: str = ""
    platform: Platform
    network: typing.Optional[Network] = None
    primary_name: typing.Optional[str] = None
    is_primary: bool = False
    resolved_address: typing.List[Address] = strawberry.field(default_factory=list)
    owner_address: typing.List[Address] = strawberry.field(default_factory=list)
    expired_at: typing.Optional[datetime] = None
    profile: typing.Optional[Profile] = None
    # No identity_graph field to prevent further queries

@strawberry.type
class IdentityGraph:
    graph_id: str
    vertices: typing.List[IdentityRecordSimplified] = strawberry.field(default_factory=list)
    edges: typing.List[IdentityConnection] = strawberry.field(default_factory=list)