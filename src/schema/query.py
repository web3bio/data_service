#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-28 22:21:45
LastEditors: Zella Zhong
LastEditTime: 2024-10-14 14:03:15
FilePath: /data_service/src/schema/query.py
Description: 
'''
import json
import logging
import strawberry
from pydantic import typing
from typing import Annotated, Union
from typing import Optional, List, TypeVar, Generic
from strawberry.types import Info

from scalar import Domain
from scalar.error import PlatformNotSupport
from resolver import basename_domain_query
from resolver.basename import query_basenames_by_owner, query_basenames_by_name


from resolver.fetch import batch_fetch, single_fetch, batch_fetch_all

from scalar.platform import Platform
from scalar.identity_record import IdentityRecord
from scalar.identity_graph import IdentityRecordSimplified


T = TypeVar("T")

@strawberry.input
class AbelFilter(Generic[T]):
    eq: Optional[T] = None
    # gt: Optional[T] = None
    # lt: Optional[T] = None


@strawberry.input
class WhereFilter:
    # bar: Optional[AbelFilter[int]] = None
    name: Optional[AbelFilter[str]] = None
    owner: Optional[AbelFilter[str]] = None

@strawberry.type
class Query:
    @strawberry.field
    async def identities(self, info: Info, ids: List[str]) -> List[IdentityRecordSimplified]:
        # only select profile, ignore identity_graph
        logging.debug("Query by identities batch fetch(identities=%s)", json.dumps(ids))
        vertices_setmap = {}
        for row in ids:
            item = row.split(",")
            if len(item) < 2:
                continue

            _platform = item[0]
            _identity = item[1]
            if _platform not in Platform.__members__:
                continue

            if _platform not in vertices_setmap:
                vertices_setmap[_platform] = set()

            vertices_setmap[_platform].add(_identity)

        vertices_map = {}
        for k, v in vertices_setmap.items():
            vertices_map[k] = list(v)
        result = await batch_fetch_all(info, vertices_map)
        return result

    @strawberry.field
    async def identity(self, info: Info, platform: Platform, identity: str) -> Optional[IdentityRecord]:
        logging.debug("Query by identities(platform=%s, identity=%s)", platform, json.dumps(identity))
        return await single_fetch(info, platform, identity)

    # @strawberry.field
    # async def domain(self, info: Info, platform: str, name: str) -> Domain:
    #     """ Get domain by name """
    #     logging.debug(f"Get domain by name {name}")
    #     if platform == "basenames":
    #         single_domain = await basename_domain_query(info, name)
    #         return single_domain
    #     else:
    #         return PlatformNotSupport(platform)

    # @strawberry.field
    # async def domains(self, info: Info, platform: str, where: WhereFilter) -> List[Domain]:
    #     if platform == "basenames":
    #         if where.name is not None:
    #             name = where.name.eq
    #             domains = await query_basenames_by_name(info, name)
    #             return domains
    #         elif where.owner is not None:
    #             owner = where.owner.eq
    #             domains = await query_basenames_by_owner(info, owner)
    #             return domains
    #     else:
    #         return PlatformNotSupport(platform)