#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-14 22:40:16
LastEditors: Zella Zhong
LastEditTime: 2024-10-14 23:17:29
FilePath: /data_service/src/cache/redis.py
Description: 
'''
import aioredis
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import setting

class RedisClient:
    _instance = None

    @classmethod
    async def get_instance(cls, host='localhost', port=6379, password=None, db=0) -> 'RedisClient':
        if cls._instance is None:
            cls._instance = await aioredis.from_url(
                "redis://{}:{}".format(setting.REDIS_SETTINGS["host"], setting.REDIS_SETTINGS["port"]),
                password=setting.REDIS_SETTINGS["password"],  # Fixed
                db=setting.REDIS_SETTINGS["db"]  # Fixed
            )
        return cls._instance

    @classmethod
    async def close(cls):
        if cls._instance is not None:
            await cls._instance.close()
            cls._instance = None

@asynccontextmanager
async def get_redis_client() -> AsyncGenerator[aioredis.Redis, None]:
    redis_client = await RedisClient.get_instance()
    try:
        yield redis_client
    finally:
        await redis_client.close()  # Clean up when done (if needed)
