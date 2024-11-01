#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 17:59:57
LastEditors: Zella Zhong
LastEditTime: 2024-11-01 10:09:53
FilePath: /data_service/src/scalar/identity_record.py
Description: 
'''
import json
import logging
import strawberry

from enum import Enum
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
    aliases: typing.List[str] = strawberry.field(default_factory=list)
    identity: str = ""
    platform: Platform
    network: typing.Optional[Network] = None
    primary_name: typing.Optional[str] = None
    is_primary: bool = False
    resolved_address: typing.List[Address] = strawberry.field(default_factory=list)
    owner_address: typing.List[Address] = strawberry.field(default_factory=list)
    expired_at: typing.Optional[datetime] = None
    updated_at: typing.Optional[datetime] = None
    profile: typing.Optional[Profile] = None

    @strawberry.field
    async def identity_graph(self, info: Info) -> typing.Optional[IdentityGraph]:
        # from resolver.identity_graph import find_identity_graph
        # logging.debug("Querying for identityGraph for identity: %s", self.identity)
        # return await find_identity_graph(info, self.platform.value, self.identity)

        # unstoppabledomains, space_id, dotbit which identity want to get idenity graph
        # it's must use it's owner identity to query
        # Because not all of profiles are available in the database
        # need to use it's owner to query all from api
        from resolver.identity_graph import find_identity_graph_cache
        logging.debug("Querying(With Cache) for identityGraph for identity: %s", self.identity)
        return await find_identity_graph_cache(info, self.platform.value, self.identity, require_cache=True)
