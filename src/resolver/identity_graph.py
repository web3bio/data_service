#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-07 03:10:41
LastEditors: Zella Zhong
LastEditTime: 2024-10-28 02:18:24
FilePath: /data_service/src/resolver/identity_graph.py
Description: 
'''
import asyncio
import aiohttp
import copy
import json
import random
import logging

from datetime import datetime, timedelta
from sqlalchemy.inspection import inspect
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import load_only
from urllib.parse import unquote
from pydantic import typing

import setting
from session import get_session
from model import EnsnameModel
from cache.redis import RedisClient

from utils import check_evm_address, convert_camel_case, compute_namehash_nowrapped
from utils.timeutils import get_unix_microseconds, parse_time_string, get_current_time_string

from scalar.platform import Platform
from scalar.network import Network
from scalar.data_source import DataSource
from scalar.identity_graph import IdentityRecordSimplified
from scalar.profile import Profile
from scalar.identity_graph import IdentityGraph
from scalar.identity_connection import IdentityConnection, EdgeType
from scalar.error import GraphDBException


from .fetch import batch_fetch_all


async def find_identity_graph_cache(info, self_platform, self_identity, require_cache=True):
    graph_result = None
    if require_cache is False:
        # query data from db and return immediately
        logging.info("identity_graph(no cache) input %s,%s", self_platform, self_identity)
        graph_result = await get_identity_graph_from_graphdb(self_platform, self_identity)
    else:
        require_update_later, graph_result = await get_identity_graph_from_cache(
            self_platform, self_identity, 12*3600)
        if graph_result is None:
            logging.info("identity_graph missing data %s,%s", self_platform, self_identity)
            graph_result = await get_and_update_missing_identity_graph(self_platform, self_identity)
        elif graph_result == {} and require_update_later is True:
            logging.info("identity_graph has olddata and return immediately %s,%s", self_platform, self_identity)
            # Update background
            asyncio.create_task(get_and_update_missing_identity_graph(self_platform, self_identity))
        else:
            logging.info("identity_graph has been cache. %s,%s", self_platform, self_identity)

    if graph_result is None:
        return None
    if graph_result == {}:
        return None

    vertices = []
    vertices_map = {}
    edges = []
    graph_id = graph_result.get("graph_id", None)
    if graph_id is None:
        return None

    for v in graph_result["vertices"]:
        # vertices.append(IdentityRecordSimplified(
        #     id=v["id"],
        #     platform=Platform[v["platform"]],
        #     identity=v["identity"]
        # ))
        platform = v["platform"]
        identity = v["identity"]
        if platform not in vertices_map:
            vertices_map[platform] = []
        vertices_map[platform].append(identity)

    for e in graph_result["edges"]:
        edges.append(IdentityConnection(
            edge_type=e["edge_type"],
            data_source=e["data_source"],
            source=e["source_v"],
            target=e["target_v"]
        ))

    vertices = batch_fetch_all(info, vertices_map)

    # vertices, fetching_edges = batch_fetch_all(info, vertices_map)
    # TODO: return identity_record, and connection_record
    # IF edges is not equal to new connection_record
    # upgrade graph_result and update cache
    # It is mainly used to solve the problem caused by ens Hold/Resolve mismatch. 
    # This kind of `ENS` identity will not appear in the results of IdentityGraph.

    identity_graph = IdentityGraph(graph_id=graph_id, vertices=vertices, edges=edges)
    return identity_graph

async def get_and_update_missing_identity_graph(self_platform, self_identity):
    graph_result = await get_identity_graph_from_graphdb(self_platform, self_identity)

    if graph_result is None:
        asyncio.create_task(set_empty_identity_graph_to_cache(self_platform, self_identity, {}, expire_window=24*3600))
    else:
        asyncio.create_task(set_identity_graph_to_cache(self_platform, self_identity, graph_result, expire_window=24*3600))
    return graph_result

async def get_identity_graph_from_cache(self_platform, self_identity, expire_window):
    '''
    description: 
    return
        require_update_later: True, or False
        graph_result: {"graph_id": "xxx", ...} or {} or None
    '''
    try:
        redis_client = await RedisClient.get_instance()
        vid = "{},{}".format(self_platform, self_identity)
        vid_cache_key = f"unique_id:{vid}"

        vid_cache_value_bytes = await redis_client.get(vid_cache_key)
        vid_cache_value = vid_cache_value_bytes.decode("utf-8") if vid_cache_value_bytes is not None else None
        if vid_cache_value is None:
            # logging.debug(f"Cache key {vid_cache_key} = {vid_cache_value} is missing")
            return True, None

        graph_cache_key = f"graph_id:{vid_cache_value}"  # e.g. graph_id:graph_id(uuidv4) or graph_id:empty_graph_id
        graph_value_json = await redis_client.get(graph_cache_key)
        graph_result = json.loads(graph_value_json)
        updated_at = graph_result.get("updated_at", None)
        if not updated_at:
            logging.warning(f"Cache key {graph_cache_key} is missing 'updated_at'. Marking for update.")
            return True, None
        else:
            updated_at_datetime = parse_time_string(updated_at)
            now = datetime.now()
            # Compare now and updated_at, if value is expired in window
            if now - updated_at_datetime > timedelta(seconds=expire_window):
                if len(graph_result) == 1:
                    # only have one field(updated_at) is also not exist
                    # logging.debug(f"Cache key {graph_cache_key} is empty. Returning old data, but marking for update.")
                    return True, {}
                else:
                    # logging.debug(f"Cache key {graph_cache_key} is expired. Returning old data, but marking for update.")
                    return True, graph_result
            else:
                if len(graph_result) == 1:
                    # only have one field(updated_at) is also not exist
                    # logging.debug(f"Cache key {graph_cache_key} is empty. Returning old data, but marking for update.")
                    return False, {}
                else:
                    # logging.debug(f"Cache key {graph_cache_key} has been caching.")
                    return False, graph_result
    except Exception as ex:
        logging.exception(ex)
        # if cache logic is failed, just return None immediately
        return False, None

async def set_identity_graph_to_cache(self_platform, self_identity, graph_result, expire_window):
    # graph_id = graph_result["graph_id"]
    graph_id = graph_result.get("graph_id", None)
    if graph_id is None:
        logging.warning("Could not set {},{} to cache {}".format(self_platform, self_identity, graph_result))
        return
    if graph_id == "":
        logging.warning("Could not set {},{} to cache(graph_id is empty) {}".format(self_platform, self_identity, graph_result))
        return
    random_offset = random.randint(0, 30 * 60)  # Adding up to 30 minutes of randomness
    random_offset = 0
    final_expire_window = expire_window + random_offset
    graph_cache_key = f"graph_id:{graph_id}"  # e.g. graph_id:graph_id(uuidv4)
    graph_lock_key = f"{graph_cache_key}.lock"

    graph_unique_value = "{}:{}".format(graph_lock_key, get_unix_microseconds())
    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(graph_lock_key, graph_unique_value, lock_timeout=30):
            # logging.debug(f"Lock acquired for key: {graph_lock_key}")
            # Set the current time as 'updated_at' in "yyyy-mm-dd HH:MM:SS" format
            graph_result["updated_at"] = get_current_time_string()
            graph_value_json = json.dumps(graph_result)

            # Set the cache in Redis with the specified expiration time (in seconds)
            redis_client = await RedisClient.get_instance()
            await redis_client.set(graph_cache_key, graph_value_json, ex=final_expire_window)
            # logging.debug(f"Cache updated for key: {graph_cache_key}")
        else:
            logging.warning(f"Could not acquire lock for key: {graph_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(graph_lock_key, graph_unique_value)
        # logging.debug(f"Lock released for key: {graph_lock_key}")

    vertices = graph_result["vertices"]
    if len(vertices) == 0:
        return

    vertex_ids = set()
    vertex_ids.add("{},{}".format(self_platform, self_identity))
    for v in vertices:
        vertex_ids.add(v["id"])

    vertex_ids = list(vertex_ids)
    vertices_lock_key = f"unique_id:{graph_id}.lock"
    vertices_unique_value = "{}:{}".format(vertices_lock_key, get_unix_microseconds())
    # logging.debug("identity_graph set vids=[{}] to graph_id={}".format(vertex_ids, graph_id))
    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(vertices_lock_key, vertices_unique_value, lock_timeout=30):
            # logging.debug(f"Lock acquired for key: {vertices_lock_key}")
            redis_client = await RedisClient.get_instance()
            for vid in vertex_ids:
                vid_cache_key = f"unique_id:{vid}"
                # Save the mapping from[vid_key] to [real graph_id]
                await redis_client.set(vid_cache_key, graph_id, ex=final_expire_window)
            # logging.debug(f"Cache updated [{vertices_lock_key}] map to key[{graph_id}]")
        else:
            logging.warning(f"Could not acquire lock for key: {vertices_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(vertices_lock_key, vertices_unique_value)
        # logging.debug(f"Lock released for key: {vertices_lock_key}")

async def set_empty_identity_graph_to_cache(self_platform, self_identity, empty_graph_result, expire_window):
    empty_graph_id = "empty_graph_id"
    random_offset = random.randint(0, 30 * 60)  # Adding up to 30 minutes of randomness
    random_offset = 0
    final_expire_window = expire_window + random_offset
    graph_cache_key = f"graph_id:{empty_graph_id}"  # e.g. graph:empty_graph_id
    graph_lock_key = f"{graph_cache_key}.lock"

    graph_unique_value = "{}:{}".format(graph_lock_key, get_unix_microseconds())
    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(graph_lock_key, graph_unique_value, lock_timeout=30):
            # logging.debug(f"Lock acquired for key: {graph_lock_key}")
            # Set the current time as 'updated_at' in "yyyy-mm-dd HH:MM:SS" format
            empty_graph_result["updated_at"] = get_current_time_string()
            graph_value_json = json.dumps(empty_graph_result)

            # Set the cache in Redis with the specified expiration time (in seconds)
            redis_client = await RedisClient.get_instance()
            await redis_client.set(graph_cache_key, graph_value_json, ex=final_expire_window)
            # logging.debug(f"Cache updated for key: {graph_cache_key}")
        else:
            logging.warning(f"Could not acquire lock for key: {graph_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(graph_lock_key, graph_unique_value)
        # logging.debug(f"Lock released for key: {graph_lock_key}")

    empty_vertex_id = "{},{}".format(self_platform, self_identity)
    vertices_lock_key = f"unique_id:{empty_vertex_id}.lock"
    vertices_unique_value = "{}:{}".format(vertices_lock_key, get_unix_microseconds())
    # logging.debug("identity_graph set vid=[{}] to empty_graph_id".format(empty_vertex_id))

    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(vertices_lock_key, vertices_unique_value, lock_timeout=30):
            # logging.debug(f"Lock acquired for key: {vertices_lock_key}")
            redis_client = await RedisClient.get_instance()
            vid_cache_key = f"unique_id:{empty_vertex_id}"
            # Save the mapping from[vid_key] to [real graph_id]
            await redis_client.set(vid_cache_key, empty_graph_id, ex=final_expire_window)
            # logging.debug(f"Cache updated [{vid_cache_key}] map to key[{empty_graph_id}]")
        else:
            logging.warning(f"Could not acquire lock for key: {vertices_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(vertices_lock_key, vertices_unique_value)
        # logging.debug(f"Lock released for key: {vertices_lock_key}")

async def get_identity_graph_from_graphdb(self_platform, self_identity):
    '''
    description:
    find_identity_graph query:
    curl -X GET 'http://hostname:restpp_port/restpp/query/SocialGraph/find_identity_graph?platform=VALUE&identity&[reverse_flag=VALUE]
    '''
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + setting.TIGERGRAPH_SETTINGS["social_graph_token"]
    }

    query_url = "http://{}:{}/restpp/query/{}/find_identity_graph?platform={}&identity={}&reverse_flag=0".format(
        setting.TIGERGRAPH_SETTINGS["host"],
        setting.TIGERGRAPH_SETTINGS["restpp"],
        setting.TIGERGRAPH_SETTINGS["social_graph_name"],
        self_platform,
        self_identity
    )

    logging.info("get_identity_graph_from_graphdb %s", query_url)
    graph_id = None
    result = {}
    async with aiohttp.ClientSession() as session:
        async with session.get(url=query_url, headers=headers, timeout=60) as response:
            raw_text = await response.text()
            res = json.loads(raw_text)

            if "error" in res and res["error"] is True:
                error_msg = "graphdb find_identity_graph[{},{}] failed:, error={}".format(self_platform, self_identity, res)
                logging.error(error_msg)
                return GraphDBException(error_msg)

            results = res.get("results", [])
            if len(results) == 0:
                graph_id = None
                result = {}
            else:
                result = results[0]
                graph_id = result["graph_id"]

    if graph_id is None:
        return None

    return result

async def find_identity_graph(info, self_platform, self_identity):
    '''
    description:
    find_identity_graph query:
    curl -X GET 'http://hostname:restpp_port/restpp/query/SocialGraph/find_identity_graph?platform=VALUE&identity&[reverse_flag=VALUE]
    '''
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + setting.TIGERGRAPH_SETTINGS["social_graph_token"]
    }

    query_url = "http://{}:{}/restpp/query/{}/find_identity_graph?platform={}&identity={}&reverse_flag=0".format(
        setting.TIGERGRAPH_SETTINGS["host"],
        setting.TIGERGRAPH_SETTINGS["restpp"],
        setting.TIGERGRAPH_SETTINGS["social_graph_name"],
        self_platform,
        self_identity
    )
    logging.info("find_identity_graph %s", query_url)
    vertices = []
    vertices_map = {}
    edges = []
    graph_id = None
    async with aiohttp.ClientSession() as session:
        async with session.get(url=query_url, headers=headers, timeout=60) as response:
            raw_text = await response.text()
            res = json.loads(raw_text)

            if "error" in res and res["error"] is True:
                error_msg = "graphdb find_identity_graph[{},{}] failed:, error={}".format(self_platform, self_identity, res)
                logging.error(error_msg)
                return GraphDBException(error_msg)

            results = res.get("results", [])
            if len(results) > 0:
                result = results[0]
                graph_id = result["graph_id"]
                for v in result["vertices"]:
                    # vertices.append(IdentityRecordSimplified(
                    #     id=v["id"],
                    #     platform=Platform[v["platform"]],
                    #     identity=v["identity"]
                    # ))
                    platform = v["platform"]
                    identity = v["identity"]
                    if platform not in vertices_map:
                        vertices_map[platform] = []
                    vertices_map[platform].append(identity)

                for e in result["edges"]:
                    edges.append(IdentityConnection(
                        edge_type=e["edge_type"],
                        data_source=e["data_source"],
                        source=e["source_v"],
                        target=e["target_v"]
                    ))

    if graph_id is None:
        return None

    # vertices and edges, replace with batch query
    # Notice:
    # Use asyncio.gather, which allows run multiple asynchronous tasks in parallel.
    # This method can avoid sequentially awaiting each query and instead run them all concurrently, 
    # making the process more efficient.
    vertices = batch_fetch_all(info, vertices_map)

    identity_graph = IdentityGraph(graph_id=graph_id, vertices=vertices, edges=edges)
    return identity_graph
