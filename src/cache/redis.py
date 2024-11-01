#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-14 22:40:16
LastEditors: Zella Zhong
LastEditTime: 2024-11-01 10:08:14
FilePath: /data_service/src/cache/redis.py
Description: 
'''
import logging
import aioredis
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from aioredis.exceptions import ConnectionError, ResponseError

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
    async def add_to_set(cls, set_key: str, values, ex: int = None):
        if isinstance(values, list):
            values = set(values)  # Ensure no duplicates before adding
        redis_client = await cls.get_instance()
        try:
            # Delete the existing set
            # await redis_client.delete(set_key)

            # Use SADD with unpacked values
            await redis_client.sadd(set_key, *values)
            # logging.info(f"Added {values} to Redis set: {set_key}")
            # Set expiration if `ex` parameter is provided
            if ex is not None:
                await redis_client.expire(set_key, ex)
                # logging.info(f"Set expiration for key: {set_key} to {ex} seconds")

        except Exception as e:
            logging.error(f"Failed to add to set for redis {set_key}. Error: {e}")


    @classmethod
    async def get_set(cls, set_key: str):
        redis_client = await cls.get_instance()
        try:
            # Retrieve all members of the set
            members = await redis_client.smembers(set_key)
            return set(m.decode("utf-8") for m in members)  # Decode bytes to strings if needed
        except Exception as e:
            logging.error(f"Failed to get set from redis {set_key}. Error: {e}")
            return set()

    @classmethod
    async def acquire_lock(cls, key: str, unique_value: str, lock_timeout: int = 10) -> bool:
        redis_client = await cls.get_instance()
        # Try to set the lock using SETNX with the passed unique value
        lock_acquired = await redis_client.setnx(key, unique_value)
        if lock_acquired:
            # Set an expiration time on the lock (to avoid stale locks)
            await redis_client.expire(key, lock_timeout)
            return True  # Lock successfully acquired
        return False  # Lock was not acquired

    @classmethod
    async def release_lock(cls, key: str, unique_value: str):
        try:
            redis_client = await cls.get_instance()

            # Lua script to ensure atomic check-and-delete operation
            release_script = """
            if redis.call("get", KEYS[1]) == ARGV[1] then
                return redis.call("del", KEYS[1])
            else
                return 0
            end
            """

            # Attempt to release the lock only if the stored value matches the unique_value
            try:
                result = await redis_client.eval(release_script, 1, key, unique_value)
                if result == 1:
                    logging.debug("Lock released for key: %s", key)
                else:
                    logging.warning("Lock release failed for key: %s, value did not match", key)

            except (ConnectionError, ResponseError) as e:
                logging.warning("ConnectionError | ResponseError: Redis connection error during release_lock for key: {}. Error: {}".format(key, e))

        except ConnectionError as e:
            logging.error("ConnectionError: Failed to connect to Redis in release_lock for key: {}. Error: {}".format(key, e))
        except Exception as e:
            logging.error("OtherError: Failed to connect to Redis in release_lock for key: {}. Error: {}".format(key, e))

@asynccontextmanager
async def get_redis_client() -> AsyncGenerator[aioredis.Redis, None]:
    redis_client = await RedisClient.get_instance()
    try:
        yield redis_client
    finally:
        await redis_client.close()  # Clean up when done (if needed)
