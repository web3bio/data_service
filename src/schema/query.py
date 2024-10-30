#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-28 22:21:45
LastEditors: Zella Zhong
LastEditTime: 2024-10-28 16:29:55
FilePath: /data_service/src/schema/query.py
Description: 
'''
import os
import jwt
import json
import logging
import strawberry

from jwt.exceptions import ExpiredSignatureError, DecodeError, InvalidTokenError
from pydantic import typing
from typing import Annotated, Union
from typing import Optional, List, TypeVar, Generic, Mapping
from fastapi import HTTPException

from strawberry.types import Info
from starlette.requests import Request
from starlette.websockets import WebSocket
from strawberry.permission import BasePermission

from scalar import Domain
from scalar.error import PlatformNotSupport

import setting
from cache.redis import RedisClient

from resolver.fetch import single_fetch, batch_fetch_all

from scalar.platform import Platform
from scalar.identity_record import IdentityRecord
from scalar.identity_graph import IdentityRecordSimplified


class RateLimitPermission(BasePermission):
    message = "Not authenticated"

    async def has_permission(self, source: typing.Any, info: typing.Any, **kwargs):
        # Global Redis instance
        redis_client = await RedisClient.get_instance()
        bearer_token = info.context["request"].headers.get("Authorization")

        # Remove "Bearer " prefix from the token if present
        token = None
        if bearer_token is not None:
            if bearer_token.startswith("Bearer "):
                token = bearer_token.split(" ")[1]  # Correctly remove 'Bearer ' prefix
            else:
                token = bearer_token  # If no 'Bearer ' prefix, use the token as is

        client_ip = info.context["request"].client.host
        # If no token, apply stricter rate limiting
        if not token:
            return await self.apply_rate_limiting(redis_client, client_ip)

        # Validate the token if present
        is_valid_token = await self.validate_token(token)

        if not is_valid_token:
            raise HTTPException(status_code=403, detail="Forbidden: Invalid token")

        # If the token is valid, proceed to apply rate limiting
        return await self.apply_rate_limiting(redis_client, client_ip)

    async def apply_rate_limiting(self, redis_client, client_ip):
        # requests_per_second = 1
        requests_per_minute = 40
        requests_per_day = 10000

        # Rate limit keys
        # rate_limit_key_second = f"rate_limit:sec:{client_ip}"
        rate_limit_key_minute = f"rate_limit:min:{client_ip}"
        rate_limit_key_day = f"rate_limit:day:{client_ip}"

        # # Check the second rate limit
        # second_count = await redis_client.get(rate_limit_key_second)
        # if second_count and int(second_count) >= requests_per_second:
        #     raise HTTPException(status_code=429, detail="Too Many Requests: 1 access per second limit exceeded")

        # # Increment second counter and set expiration to 1 second
        # await redis_client.incr(rate_limit_key_second)
        # await redis_client.expire(rate_limit_key_second, 1)  # Expires in 1 second

        # Check the minute rate limit
        minute_count = await redis_client.get(rate_limit_key_minute)
        if minute_count and int(minute_count) >= requests_per_minute:
            raise HTTPException(status_code=429, detail="Too Many Requests: 40 accesses per minute limit exceeded")

        # Increment minute counter and set expiration to 60 seconds
        # await redis_client.incr(rate_limit_key_minute)
        await redis_client.expire(rate_limit_key_minute, 60)  # Expires in 60 seconds

        # Check the daily rate limit
        day_count = await redis_client.get(rate_limit_key_day)
        if day_count and int(day_count) >= requests_per_day:
            raise HTTPException(status_code=429, detail="Too Many Requests: 10,000 accesses per day limit exceeded")

        # Increment daily counter and set expiration to 24 hours
        # await redis_client.incr(rate_limit_key_day)
        await redis_client.expire(rate_limit_key_day, 86400)  # Expires in 24 hours

        # If all checks pass, allow the request
        return True

    async def validate_token(self, token):
        try:
            # Validate the token
            # logging.debug("setting.AUTHENTICATE[secret] %s", setting.AUTHENTICATE["secret"])
            payload = jwt.decode(token, setting.AUTHENTICATE["secret"], algorithms=['HS256'])
            return True  # Token is valid
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.DecodeError:  # More specific than InvalidTokenError
            raise HTTPException(status_code=403, detail="Invalid token")
        except jwt.InvalidTokenError:  # Most general exception
            raise HTTPException(status_code=403, detail="Invalid token")


class IsAuthenticated(BasePermission):
    message = "User is not authenticated"

    async def has_permission(self, source: typing.Any, info: typing.Any, **kwargs) -> bool:
        request: typing.Union[Request, WebSocket] = info.context["request"]

        # Extract token from Authorization header
        token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()

        if not token:
            return False  # Token is missing

        try:
            # Validate the token
            jwt.decode(token, setting.AUTHENTICATE["secret"], algorithms=["HS256"])
            return True  # Token is valid
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return False  # Token is invalid


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
    @strawberry.field(permission_classes=[RateLimitPermission])
    async def identities(self, info: Info, ids: List[str]) -> List[IdentityRecordSimplified]:
        # only select profile, ignore identity_graph
        logging.debug("Query by identities batch fetch(identities=%s)", json.dumps(ids))
        vertices_map = {}
        for row in ids:
            item = row.split(",")
            if len(item) != 2:
                continue

            _platform = item[0]
            _identity = item[1]
            if _platform not in Platform.__members__:
                continue

            if _platform not in vertices_map:
                vertices_map[_platform] = []

            vertices_map[_platform].append(_identity)
            # vertices_map[_platform].append(row)

        result = await batch_fetch_all(info, vertices_map)
        return result

    @strawberry.field(permission_classes=[RateLimitPermission])
    async def identity(self, info: Info, platform: Platform, identity: str) -> Optional[IdentityRecord]:
        logging.debug("Query by identities(platform=%s, identity=%s)", platform, json.dumps(identity))
        return await single_fetch(info, platform, identity)
