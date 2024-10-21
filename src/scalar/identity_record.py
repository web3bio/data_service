#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 17:59:57
LastEditors: Zella Zhong
LastEditTime: 2024-10-21 15:41:30
FilePath: /data_service/src/scalar/identity_record.py
Description: 
'''
import logging
import strawberry

from datetime import datetime, timedelta
from pydantic import Field, typing
from strawberry.scalars import JSON
from strawberry.types import Info

from .network import Network, Address
from .platform import Platform
from .profile import Profile
from .identity_graph import IdentityGraph
from .identity_connection import IdentityConnection, EdgeType
from .data_source import DataSource


@strawberry.type
class IdentityRecord:
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

    @strawberry.field
    async def identity_graph(self, info: Info) -> typing.Optional[IdentityGraph]:
        from resolver.identity_graph import find_identity_graph
        logging.debug("Querying for identityGraph for identity: %s", self.identity)
        return await find_identity_graph(info, self.platform.value, self.identity)
