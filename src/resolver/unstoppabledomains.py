#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-24 17:34:05
LastEditors: Zella Zhong
LastEditTime: 2024-11-01 10:59:59
FilePath: /data_service/src/resolver/unstoppabledomains.py
Description: 
'''
import time
import ssl
import certifi
import uuid
import aiohttp
import asyncio
import copy
import json
import random
import logging
import setting

from datetime import datetime, timedelta
from sqlalchemy.inspection import inspect
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import load_only
from urllib.parse import unquote
from pydantic import typing

import strawberry

from datetime import datetime, timedelta
from sqlalchemy.inspection import inspect
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import load_only
from urllib.parse import unquote

from session import get_session, get_asyncpg_session
from model.unstoppabledomains import UnstoppabledomainsModel
from cache.redis import RedisClient

from graphdb.identity_graph import Vertex, Edge
from graphdb.identity_graph import upsert_graph, delete_all_edges_by_source
from graphdb.identity_graph import VERTEX_IDENTITY, VERTEX_IDENTITY_GRAPH, EDGE_PART_OF_IDENTITY_GRAPH, EDGE_HOLD, EDGE_PROOF, EDGE_RESOLVE, EDGE_REVERSE_RESOLVE

from utils import uint256_to_bytes32
from utils.address import is_ethereum_address
from utils.timeutils import get_unix_microseconds, get_current_time_string, parse_time_string

from scalar.platform import Platform
from scalar.network import Network, Address, CoinTypeMap
from scalar.identity_graph import IdentityRecordSimplified
from scalar.identity_record import IdentityRecord
from scalar.profile import Profile, SocialProfile
from scalar.error import DomainNotFound, EmptyInput, EvmAddressInvalid, ExceedRangeInput
from scalar.type_convert import strawberry_type_to_jsonstr

POSTFIX = ['crypto', 'wallet', 'blockchain', 'bitcoin', 'x', '888', 'nft', 'dao', 'polygon', 'unstoppable', 'pudgy', 'go', 'zil', 'austin', 'raiin', 'tball', 'farms']          

QUERY_MAX_LIMIT = 50

def convert_cache_to_identity_record(cache_value):
    try:
        if not cache_value:
            return None
        primary_id = cache_value.get('id', None)
        if primary_id is None:
            return None

        # Convert resolved_address list of dictionaries to list of Address instances
        resolved_address = [Address(**address) for address in cache_value.get("resolved_address", [])]

        # Convert owner_address list of dictionaries to list of Address instances
        owner_address = [Address(**address) for address in cache_value.get("owner_address", [])]

        platform_str = cache_value.get("platform", None)
        platform = Platform(platform_str) if platform_str else None

        network_str = cache_value.get("network", None)
        network = Network(network_str) if network_str else None

        # Convert profile dictionary to Profile instance
        profile_data = cache_value.get("profile", None)
        profile = None
        if profile_data:
            addresses = [Address(**addr) for addr in profile_data.get("addresses", [])]
            profile_platform_str = profile_data.get("platform", None)
            profile_platform = Platform(profile_platform_str) if profile_platform_str else None

            profile_network_str = profile_data.get("network", None)
            profile_network = Network(profile_network_str) if profile_network_str else None
            social_dict = profile_data.get("social", None)
            social = None
            if social_dict is not None:
                social_updated_at_str = social_dict.get("updated_at", None)
                social_updated_at = None
                if social_updated_at_str is not None:
                    social_updated_at = datetime.strptime(social_updated_at_str, "%Y-%m-%d %H:%M:%S") if social_updated_at_str else None
                social = SocialProfile(
                    uid=social_dict.get("uid", None),
                    following=social_dict.get("following", 0),
                    follower=social_dict.get("follower", 0),
                    updated_at=social_updated_at,
                )
            profile = Profile(
                uid=profile_data.get("uid"),
                identity=profile_data.get("identity"),
                platform=profile_platform,
                network=profile_network,
                address=profile_data.get("address"),
                display_name=profile_data.get("display_name"),
                avatar=profile_data.get("avatar"),
                description=profile_data.get("description"),
                contenthash=profile_data.get("contenthash"),
                texts=profile_data.get("texts", {}),
                addresses=addresses,
                social=social,
            )

        expired_at_str = cache_value.get("expired_at")
        updated_at_str = cache_value.get("updated_at")

        expired_at = datetime.strptime(expired_at_str, "%Y-%m-%d %H:%M:%S") if expired_at_str else None
        updated_at = datetime.strptime(updated_at_str, "%Y-%m-%d %H:%M:%S") if updated_at_str else None

        # Return the IdentityRecord instance
        return IdentityRecord(
            id=cache_value.get("id"),
            aliases=cache_value.get("aliases"),
            identity=cache_value.get("identity"),
            platform=platform,
            network=network,
            primary_name=cache_value.get("primary_name"),
            is_primary=cache_value.get("is_primary"),
            resolved_address=resolved_address,
            owner_address=owner_address,
            expired_at=expired_at,
            updated_at=updated_at,
            profile=profile,
        )

    except Exception as ex:
        logging.exception(ex)
        return None

async def get_unstoppabledomains_from_cache(query_ids, expire_window):
    '''
    description: get data from cache and determine if an update is required
        query_ids e.g. "unstoppabledomains,0xzella.crypto"
        expire_window: e.g., 4 hours would be 4 * 3600 = 14400 seconds
    return {
        cache_identity_records: List[IdentityRecordSimplified],
        require_update_ids: List[str], # which exist in cache but expired (return old data first to speed up response)
        missing_query_ids: List[str],  # which not exist in cache, must query_from_db
    }
    '''
    try:
        cache_identity_records = []
        require_update_ids = []
        missing_query_ids = []
        redis_client = await RedisClient.get_instance()

        aliases_keys = []
        for query_id in query_ids:
            aliases_keys.append(f"aliases:{query_id}")
        aliases_keys = list(set(aliases_keys))

        aliases_values = await redis_client.mget(*aliases_keys)
        aliases_cache_item = dict(zip(aliases_keys, aliases_values))

        profile_map_aliases_key = {}
        for alias_cache_key_bytes, profile_cache_key_bytes in aliases_cache_item.items():
            alias_cache_key = alias_cache_key_bytes.decode("utf-8") if isinstance(alias_cache_key_bytes, bytes) else alias_cache_key_bytes
            profile_cache_key = profile_cache_key_bytes.decode("utf-8") if profile_cache_key_bytes is not None else None

            if profile_cache_key is None:
                missing_query_ids.append(alias_cache_key.removeprefix("aliases:"))
            else:
                if profile_cache_key not in profile_map_aliases_key:
                    profile_map_aliases_key[profile_cache_key] = []
                profile_map_aliases_key[profile_cache_key].append(alias_cache_key.removeprefix("aliases:"))

        batch_profile_cache_keys = list(profile_map_aliases_key.keys())
        if batch_profile_cache_keys:
            profile_json_values = await redis_client.mget(*batch_profile_cache_keys)
            profile_cache_json_values = dict(zip(batch_profile_cache_keys, profile_json_values))
            for profile_cache_key_bytes, profile_json_value_bytes in profile_cache_json_values.items():
                profile_cache_key = profile_cache_key_bytes.decode("utf-8") if isinstance(profile_cache_key_bytes, bytes) else profile_cache_key_bytes
                profile_json_value = profile_json_value_bytes.decode("utf-8") if profile_json_value_bytes is not None else None

                if profile_json_value is None:
                    # add aliases:platform,alias_value to missing_query_ids
                    missing_query_ids.append(profile_cache_key.removeprefix("profile:"))
                    missing_aliases_ids = profile_map_aliases_key.get(profile_cache_key, [])
                    missing_query_ids.extend(missing_aliases_ids)
                else:
                    profile_value_dict = json.loads(profile_json_value)
                    updated_at = profile_value_dict.get("updated_at", None)
                    if not updated_at:
                        logging.warning(f"Cache key {profile_cache_key} is missing 'updated_at'. Marking for update.")
                        missing_query_ids.append(profile_cache_key.removeprefix("profile:"))
                    else:
                        updated_at_datetime = parse_time_string(updated_at)
                        now = datetime.now()
                        # Compare now and updated_at, if value is expired in window
                        if now - updated_at_datetime > timedelta(seconds=expire_window):
                            if len(profile_value_dict) == 1:
                                # only have one field(updated_at) is also not exist
                                # logging.debug(f"Cache key {profile_cache_key} is empty. Returning old data, but marking for update.")
                                require_update_ids.append(profile_cache_key.removeprefix("profile:"))
                            else:
                                # Old data is returned, but it needs to be updated
                                # logging.debug(f"Cache key {profile_cache_key} is expired. Returning old data, but marking for update.")
                                require_update_ids.append(profile_cache_key.removeprefix("profile:"))
                                identity_record = convert_cache_to_identity_record(profile_value_dict)
                                if identity_record:
                                    cache_identity_records.append(identity_record)
                        else:
                            if len(profile_value_dict) == 1:
                                # only have one field(updated_at) is also not exist
                                # logging.debug(f"Cache key {profile_cache_key} is empty but has been caching.")
                                continue
                            else:
                                # logging.debug(f"Cache key {profile_cache_key} has been caching.")
                                identity_record = convert_cache_to_identity_record(profile_value_dict)
                                if identity_record:
                                    cache_identity_records.append(identity_record)

        return cache_identity_records, require_update_ids, missing_query_ids
    except Exception as ex:
        logging.exception(ex)
        # if cache logic is failed, just return query_from_db immediately
        return [], [], query_ids

async def set_unstoppabledomains_to_cache(cache_identity_record: IdentityRecordSimplified, expire_window):
    '''
    description: set data into the cache with a Redis lock to prevent concurrency issues
        primary_id: "platform,identity", # e.g., "unstoppabledomains,0xzella.crypto"
        expire_window: e.g., 4 hours would be 4 * 3600 = 14400 seconds
        expire_window may longer that 4 hours and add some random seconds to avoid batch key expiration issues
    return {*}
    '''
    random_offset = random.randint(0, 30 * 60)  # Adding up to 30 minutes of randomness
    # random_offset = 0
    final_expire_window = expire_window + random_offset

    primary_id = cache_identity_record.id
    profile_cache_key = f"profile:{primary_id}"  # e.g. profile:unstoppabledomains,0xzella.crypto
    profile_lock_key = f"{profile_cache_key}.lock"

    profile_unique_value = "{}:{}".format(profile_lock_key, get_unix_microseconds())
    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(profile_lock_key, profile_unique_value, lock_timeout=30):
            # logging.debug(f"Lock acquired for key: {profile_lock_key}")
            # Set the current time as 'updated_at' in "yyyy-mm-dd HH:MM:SS" format
            cache_identity_record.updated_at = datetime.now()
            profile_value_json = strawberry_type_to_jsonstr(cache_identity_record)

            # Set the cache in Redis with the specified expiration time (in seconds)
            redis_client = await RedisClient.get_instance()
            await redis_client.set(profile_cache_key, profile_value_json, ex=final_expire_window)
            # logging.debug(f"Cache updated for key: {profile_cache_key}")
        else:
            logging.warning(f"Could not acquire lock for key: {profile_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(profile_lock_key, profile_unique_value)
        # logging.debug(f"Lock released for key: {profile_lock_key}")

    if len(cache_identity_record.aliases) == 0:
        return

    aliases_lock_key = f"aliases:{primary_id}.lock"
    aliases_unique_value = "{}:{}".format(aliases_lock_key, get_unix_microseconds())
    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(aliases_lock_key, aliases_unique_value, lock_timeout=30):
            # logging.debug(f"Lock acquired for key: {aliases_lock_key}")
            redis_client = await RedisClient.get_instance()
            for alias in cache_identity_record.aliases:
                # alias_cache_key: e.g. f"aliases:{platform,identity}"
                # Save the mapping from[alias_key] to [real profile_key]
                alias_cache_key = f"aliases:{alias}"
                await redis_client.set(alias_cache_key, profile_cache_key, ex=final_expire_window)
            # logging.debug(f"Cache updated aliases[{aliases_lock_key}] map to key[{profile_cache_key}]")
        else:
            logging.warning(f"Could not acquire lock for key: {aliases_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(aliases_lock_key, aliases_unique_value)
        # logging.debug(f"Lock released for key: {aliases_lock_key}")

async def batch_set_unstoppabledomains_to_cache(
    cache_identity_records: typing.List[IdentityRecordSimplified], expire_window: int
):
    """
    Description: Batch set data into the cache and set expiration times using a Lua script.
    Args:
        cache_identity_records (List[IdentityRecordSimplified]): List of cache identity records to store.
        expire_window (int): Expiration window in seconds.
    """
    random_offset = random.randint(0, 30 * 60)  # Adding up to 30 minutes of randomness
    # random_offset = 0
    final_expire_window = expire_window + random_offset

    profile_data = {}
    aliases_data = {}
    keys_with_expiration = []

    for record in cache_identity_records:
        primary_id = record.id
        profile_cache_key = f"profile:{primary_id}"
        # Set the current time as 'updated_at'
        # in "yyyy-MM-dd HH:MM:SS" format later in strawberry_type_to_jsonstr
        record.updated_at = datetime.now()
        profile_value_json = strawberry_type_to_jsonstr(record)
        profile_data[profile_cache_key] = profile_value_json
        keys_with_expiration.append(profile_cache_key)

        if record.aliases:
            for alias in record.aliases:
                alias_cache_key = f"aliases:{alias}"
                aliases_data[alias_cache_key] = profile_cache_key
                keys_with_expiration.append(alias_cache_key)

    redis_client = await RedisClient.get_instance()

    # Use MSET to set all profile data
    if profile_data:
        await redis_client.mset(profile_data)
    if aliases_data:
        await redis_client.mset(aliases_data)

    # Use a Lua script to set expiration for all keys at once
    if keys_with_expiration:
        # Lua script to set expiration for multiple keys
        lua_script = """
        for i, key in ipairs(KEYS) do
            redis.call("EXPIRE", key, tonumber(ARGV[1]))
        end
        """
        # await redis_client.eval(lua_script, keys=keys_with_expiration, args=[final_expire_window])
        await redis_client.eval(lua_script, len(keys_with_expiration), *keys_with_expiration, final_expire_window)

    logging.info("Batch set profiles and aliases successfully, with expirations set.")

async def set_empty_unstoppabledomains_profile_to_cache(query_id, empty_record, expire_window):
    random_offset = random.randint(0, 30 * 60)  # Adding up to 30 minutes of randomness
    # random_offset = 0
    final_expire_window = expire_window + random_offset

    profile_cache_key = f"profile:{query_id}"  # e.g. profile:ud,#notexist_profile_id which is not exist
    profile_lock_key = f"{query_id}.lock"

    profile_unique_value = "{}:{}".format(profile_lock_key, get_unix_microseconds())
    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(profile_lock_key, profile_unique_value, lock_timeout=30):
            # logging.debug(f"Lock acquired for key: {profile_lock_key}")
            # Set the current time as 'updated_at' in "yyyy-mm-dd HH:MM:SS" format
            empty_record["updated_at"] = get_current_time_string()
            profile_value_json = json.dumps(empty_record)

            # Set the cache in Redis with the specified expiration time (in seconds)
            redis_client = await RedisClient.get_instance()
            await redis_client.set(profile_cache_key, profile_value_json, ex=final_expire_window)
            # logging.debug(f"Cache updated for key: {profile_cache_key}")
        else:
            logging.warning(f"Could not acquire lock for key: {profile_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(profile_lock_key, profile_unique_value)
        # logging.debug(f"Lock released for key: {profile_lock_key}")

    aliases_lock_key = f"aliases:{query_id}.lock"
    aliases_unique_value = "{}:{}".format(aliases_lock_key, get_unix_microseconds())
    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(aliases_lock_key, aliases_unique_value, lock_timeout=30):
            # logging.debug(f"Lock acquired for key: {aliases_lock_key}")
            redis_client = await RedisClient.get_instance()
            # Save the empty query_id to [profile_key], and profile_key only have updated_at
            alias_cache_key = f"aliases:{query_id}"
            await redis_client.set(alias_cache_key, profile_cache_key, ex=final_expire_window)
            # logging.debug(f"Cache updated aliases[{aliases_lock_key}] map to key[{profile_cache_key}]")
        else:
            logging.warning(f"Could not acquire lock for key: {aliases_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(aliases_lock_key, aliases_unique_value)
        # logging.debug(f"Lock released for key: {aliases_lock_key}")

async def get_domains_by_name(domain_name):
    '''
    description:
    https://api.unstoppabledomains.com/resolve/domains/domain_name
    '''
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + setting.UPSTREAM["unstoppabledomains_api"]["api_key"],
    }
    query_url = "{}/resolve/domains/{}".format(
        setting.UPSTREAM["unstoppabledomains_api"]["api"],
        domain_name
    )
    logging.debug("unstoppabledomains get_domains_by_name %s", query_url)

    domains = []

    ssl_context = ssl.create_default_context(cafile=certifi.where())
    async with aiohttp.ClientSession() as http_session:
        async with http_session.get(url=query_url, headers=headers, timeout=30, ssl=ssl_context) as response:
            if response.status != 200:
                error_msg = "unstoppabledomains get_domains_by_name failed: name={}, {} {}".format(
                    domain_name, response.status, response.reason)
                logging.error(error_msg)
                raise Exception(error_msg)

            raw_text = await response.text()
            res = json.loads(raw_text)

            code = res.get("code", None)
            message = res.get("message", None)
            if code is not None or message is not None:
                error_msg = "unstoppabledomains get_domains_by_name failed: name={}, {} {}".format(
                    domain_name, code, message)
                logging.error(error_msg)
                raise Exception(error_msg)

            metadata = res.get("meta", None)
            if metadata is not None:
                name = metadata.get("domain", None)
                namenode = metadata.get("namehash", None)
                network_id = metadata.get("networkId", None)
                # only save MATIC (ignored Ethereum)
                if name is not None and namenode is not None and network_id == 137:
                    if name.find('.') != -1:
                        name_postfix = name.split('.')[-1]
                        if name_postfix in POSTFIX:
                            reverse_address = None
                            owner = metadata.get("owner", None)
                            if owner is not None and owner != "0x000000000000000000000000000000000000":
                                owner = owner.lower()
                                reverse = metadata.get("reverse", False)
                                if reverse:
                                    reverse_address = owner
                                domain_item = {
                                    "namenode": namenode,
                                    "name": name,
                                    "label_name": name.split('.')[0],
                                    "label": uint256_to_bytes32(metadata.get("tokenId", None)),
                                    "erc721_token_id": metadata.get("tokenId", None),
                                    "registry": metadata.get("registry", None),
                                    "owner": owner,
                                    "resolver": metadata.get("resolver", None),
                                    "resolved_address": owner,
                                    "reverse_address": reverse_address,
                                    "is_primary": reverse,
                                    "update_time": datetime.now(),
                                    # "update_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(time.time()))),
                                    "texts": {},
                                }

                                records = res.get("records", {})
                                domain_item["texts"] = records
                                domains.append(domain_item)

    return domains

async def get_domains_by_owner(owner_address):
    '''
    description: 
    https://api.unstoppabledomains.com/resolve/domains?owners=owner_address&startingAfter={}
    '''
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + setting.UPSTREAM["unstoppabledomains_api"]["api_key"],
    }
    domains = []
    cnt = 0
    hasMore = True
    nextStartingAfter = None
    domain_count = 0
    # 30 * 100 perPage = 3000, maxlimit
    while(hasMore):
        query_url = "{}/resolve/domains?owners={}&limit=50".format(
            setting.UPSTREAM["unstoppabledomains_api"]["api"],
            owner_address
        )
        if nextStartingAfter is not None:
            query_url = "{}&startingAfter={}&limit=50".format(query_url, nextStartingAfter)

        logging.debug("unstoppabledomains get_domains_by_owner %s", query_url)

        ssl_context = ssl.create_default_context(cafile=certifi.where())
        async with aiohttp.ClientSession() as http_session:
            async with http_session.get(url=query_url, headers=headers, timeout=30, ssl=ssl_context) as response:
                if response.status != 200:
                    error_msg = "unstoppabledomains get_domains_by_owner failed: owner={}, {} {}".format(
                        owner_address, response.status, response.reason)
                    logging.error(error_msg)
                    raise Exception(error_msg)

                raw_text = await response.text()
                res = json.loads(raw_text)

                code = res.get("code", None)
                message = res.get("message", None)
                if code is not None or message is not None:
                    error_msg = "unstoppabledomains get_domains_by_owner failed: owner={}, {} {}".format(
                        owner_address, code, message)
                    logging.error(error_msg)
                    raise Exception(error_msg)

                res_data = res.get("data", [])
                if len(res_data) == 0:
                    hasMore = False
                    nextStartingAfter = None
                    break

                for item in res_data:
                    attributes = item.get("attributes", None)
                    if attributes is not None:
                        metadata = attributes.get("meta", None)
                        if metadata is not None:
                            name = metadata.get("domain", None)
                            namenode = metadata.get("namehash", None)
                            network_id = metadata.get("networkId", None)
                            # only save MATIC (ignored Ethereum)
                            if name is not None and namenode is not None and network_id == 137:
                                reverse_address = None
                                owner = metadata.get("owner", None)
                                if owner is None or owner == "0x000000000000000000000000000000000000":
                                    continue
                                if name.find('.') != -1:
                                    name_postfix = name.split('.')[-1]
                                    if name_postfix not in POSTFIX:
                                        continue

                                owner = owner.lower()
                                reverse = metadata.get("reverse", False)
                                if reverse:
                                    reverse_address = owner
                                domain_item = {
                                    "namenode": namenode,
                                    "name": name,
                                    "label_name": name.split('.')[0],
                                    "label": uint256_to_bytes32(metadata.get("tokenId", None)),
                                    "erc721_token_id": metadata.get("tokenId", None),
                                    "registry": metadata.get("registry", None),
                                    "owner": owner,
                                    "resolver": metadata.get("resolver", None),
                                    "resolved_address": owner,
                                    "reverse_address": reverse_address,
                                    "is_primary": reverse,
                                    "update_time": datetime.now(),
                                    "texts": {},
                                }

                                records = res.get("records", {})
                                domain_item["texts"] = records
                                domains.append(domain_item)
                                domain_count += 1
                                if domain_count > QUERY_MAX_LIMIT:
                                    hasMore = False
                                    nextStartingAfter = None
                                    break

                if domain_count > QUERY_MAX_LIMIT:
                    hasMore = False
                    nextStartingAfter = None
                    break

                cnt += 1
                page_meta = res.get("meta", None)
                if page_meta is not None:
                    hasMore = page_meta.get("hasMore", False)
                    nextStartingAfter = page_meta.get("nextStartingAfter", None)
                else:
                    hasMore = False
                    nextStartingAfter = None
                    break

                if cnt > 30:
                    break

    return domains

async def batch_query_domains_from_api(query_ids):
    result = []
    global_count = 0
    # params
    address_list = set()
    name_list = set()
    for _id in query_ids:
        identity = _id.split(",")[1]
        is_evm = is_ethereum_address(identity)
        if is_evm:
            address_list.add(identity)
        else:
            name_list.add(identity)

    address_list = list(address_list)
    name_list = list(name_list)

    unique_name = []
    if address_list:
        for owner in address_list:
            fetch_domains = await get_domains_by_owner(owner)
            if fetch_domains:
                fetch_names = [x["name"] for x in fetch_domains]
                result.extend(fetch_domains)
                unique_name.extend(fetch_names)
                global_count += len(fetch_names)

    unique_name = set(unique_name)
    if global_count < QUERY_MAX_LIMIT:
        domain_owners = []
        if name_list:
            for domain_name in name_list:
                if domain_name not in unique_name:
                    global_count += 1
                    if global_count > QUERY_MAX_LIMIT:
                        break
                    fetch_domains = await get_domains_by_name(domain_name)
                    if fetch_domains:
                        for item in fetch_domains:
                            if item["owner"] != "0x000000000000000000000000000000000000":
                                result.append(item)
                                domain_owners.append(item["owner"].lower())
        if global_count < QUERY_MAX_LIMIT:
            # check the missing addresses
            if domain_owners:
                for owner in domain_owners:
                    if owner not in address_list:
                        fetch_domains = await get_domains_by_owner(owner)
                        if fetch_domains:
                            result.extend(fetch_domains)

    unique_result = []
    unique_result_set = set()
    for r in result:
        if r["name"] not in unique_result_set:
            unique_result_set.add(r["name"])
            unique_result.append(r)

    return unique_result

def match_unstoppabledomains_profile_records(domains):
    identity_records = []
    for domain in domains:
        name = domain.get("name", None)
        owner = domain.get("owner", None)
        if not name or not owner:
            continue

        primary_id = "{},{}".format(Platform.unstoppabledomains.value, name)
        resolved_address = domain.get("resolved_address", None)
        reverse_address = domain.get("reverse_address", None)
        is_primary = domain.get("is_primary", False)

        aliases = [primary_id]
        if is_primary and reverse_address:
            aliases.append(f"{Platform.unstoppabledomains.value},{reverse_address}")

        address = None
        network = None
        resolved_addresses = []
        owner_addresses = []
        records = []

        if owner is not None:
            address = owner
            network = Network.ethereum
            owner_addresses.append(Address(address=owner, network=Network.ethereum))
            records.append(Address(address=owner, network=Network.ethereum))

        if resolved_address is not None:
            resolved_addresses.append(Address(address=resolved_address, network=Network.ethereum))
            if address is None or network is None:
                address = resolved_address
                network = Network.ethereum

        # TODO: unstoppabledomains records:
        # crypto.* — Records related to crypto payments
        # dns.* — DNS records
        # dweb.* — Records related to distributed content network protocols
        # browser.* — Hint records for web browsers
        texts = domain.get("texts", {})
        if not texts:
            texts = None

        profile = Profile(
            uid=None,
            identity=name,
            platform=Platform.unstoppabledomains,
            network=network,
            address=address,
            display_name=name,
            avatar=None,
            description=None,
            texts=texts,
            addresses=records,
            social=None,
        )
        identity_records.append(IdentityRecordSimplified(
            id=primary_id,
            aliases=aliases,
            identity=name,
            platform=Platform.unstoppabledomains,
            network=network,
            primary_name=None,
            is_primary=is_primary,
            expired_at=None,
            resolved_address=resolved_addresses,
            owner_address=owner_addresses,
            profile=profile
        ))

    return identity_records

async def save_unstoppabledomains_profile_to_db(domains):
    owner_unique_ids = set()
    for domain in domains:
        owner_address = domain.get('owner', None)
        owner_unique_id = f"{Platform.ethereum.value},{owner_address}"
        owner_unique_ids.add(owner_unique_id)

    owner_unique_ids = list(owner_unique_ids)
    if not owner_unique_ids:
        return

    address_unique_mapping_graph_id = {}
    try:
        select_sql = "SELECT unique_id, graph_id, updated_nanosecond, platform, identity FROM graph_id WHERE unique_id = ANY($1)"
        async with get_asyncpg_session() as conn:
            rows = await conn.fetch(select_sql, owner_unique_ids)
            for row in rows:
                address_unique_mapping_graph_id[row["unique_id"]] = {
                    "graph_id": row["graph_id"],
                    "updated_nanosecond": row["updated_nanosecond"],
                    "platform": row["platform"],
                    "identity": row["identity"]
                }

        # Add a graph_id to the non-existent owner
        for owner_unique_id in owner_unique_ids:
            if owner_unique_id not in address_unique_mapping_graph_id:
                address_unique_mapping_graph_id[owner_unique_id] = {
                    "graph_id": str(uuid.uuid4()),
                    "updated_nanosecond": get_unix_microseconds(),
                    "platform": Platform.ethereum.value,
                    "identity": owner_address.removeprefix(f"{Platform.ethereum.value},")
                }

        graph_id_upsert_sql = """
        INSERT INTO graph_id (
            unique_id, graph_id, updated_nanosecond, platform, identity, picked_time
        ) VALUES (
            $1, $2, $3, $4, $5, $6
        )
        ON CONFLICT (unique_id) DO UPDATE SET
            unique_id = EXCLUDED.unique_id,
            graph_id = EXCLUDED.graph_id,
            updated_nanosecond = EXCLUDED.updated_nanosecond,
            platform = EXCLUDED.platform,
            identity = EXCLUDED.identity,
            picked_time = EXCLUDED.picked_time;
        """

        upsert_sql = """
        INSERT INTO unstoppabledomains (
            namenode, name, label_name, label,
            erc721_token_id, registry, owner,
            resolver, resolved_address,
            reverse_address, is_primary, texts,
            update_time
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
        )
        ON CONFLICT (namenode) DO UPDATE SET
            name = EXCLUDED.name,
            label_name = EXCLUDED.label_name,
            label = EXCLUDED.label,
            erc721_token_id = EXCLUDED.erc721_token_id,
            registry = EXCLUDED.registry,
            owner = EXCLUDED.owner,
            resolver = EXCLUDED.resolver,
            resolved_address = EXCLUDED.resolved_address,
            reverse_address = EXCLUDED.reverse_address,
            is_primary = EXCLUDED.is_primary,
            texts = EXCLUDED.texts,
            update_time = EXCLUDED.update_time;
        """

        vertices = []
        edges = []
        domain_unique_ids = []
        updated_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
        upsert_graph_id_values = []
        upsert_values = []
        for domain in domains:
            upsert_values.append((
                domain["namenode"], domain["name"], domain["label_name"],
                domain["label"], domain["erc721_token_id"], domain["registry"],
                domain["owner"], domain["resolver"], domain["resolved_address"],
                domain["reverse_address"], domain["is_primary"],
                json.dumps(domain["texts"]),
                domain["update_time"]
            ))
            name = domain.get('name', None)
            owner_address = domain.get('owner', None)
            # unstoppabledomains owner_address always equals to resolved_address
            resolved_address = domain.get('resolved_address', None)
            is_primary = domain.get('is_primary', False)
            reverse_address = domain.get('reverse_address', False)

            owner_address_id = f"{Platform.ethereum.value},{owner_address}"
            if owner_address_id in address_unique_mapping_graph_id:
                address_graph_id = address_unique_mapping_graph_id[owner_unique_id]["graph_id"]
                address_updated_nanosecond = address_unique_mapping_graph_id[owner_unique_id]["updated_nanosecond"]
                domain_unique_id = f"{Platform.unstoppabledomains.value},{name}"
                domain_unique_ids.append(domain_unique_id)
                upsert_graph_id_values.append((
                    domain_unique_id, address_graph_id, address_updated_nanosecond,
                    Platform.unstoppabledomains.value, name, datetime.now()
                ))

                hv = {
                    "id": {"value": address_graph_id, "op": "ignore_if_exists"},
                    "updated_nanosecond": {"value": address_updated_nanosecond, "op": "ignore_if_exists"}
                }
                domain_identity = {
                    "id": {"value": domain_unique_id, "op": "ignore_if_exists"},
                    "platform": {"value": Platform.unstoppabledomains.value, "op": "ignore_if_exists"},
                    "identity": {"value": name, "op": "ignore_if_exists"},
                    "updated_at": {"value": updated_at, "op": "max"},
                }
                owner_identity = {
                    "id": {"value": owner_address_id, "op": "ignore_if_exists"},
                    "platform": {"value": Platform.ethereum.value, "op": "ignore_if_exists"},
                    "identity": {"value": owner_address, "op": "ignore_if_exists"},
                    "updated_at": {"value": updated_at, "op": "max"},
                }
                vertices.append(Vertex(
                    vertex_id=hv["id"]["value"],
                    vertex_type="IdentitiesGraph",
                    attributes=hv
                ))
                vertices.append(Vertex(
                    vertex_id=domain_identity["id"]["value"],
                    vertex_type="Identities",
                    attributes=domain_identity
                ))
                vertices.append(Vertex(
                    vertex_id=owner_identity["id"]["value"],
                    vertex_type="Identities",
                    attributes=owner_identity
                ))

                ownership = {
                    "source": {"value": Platform.unstoppabledomains.value},
                    "level": {"value": 5},
                }
                resolve_edge = {
                    "source": {"value": Platform.unstoppabledomains.value},
                    "level": {"value": 5},
                }

                edges.append(Edge(
                    edge_type="PartOfIdentitiesGraph_Reverse",
                    from_id=hv["id"]["value"],
                    from_type="IdentitiesGraph",
                    to_id=domain_identity["id"]["value"],
                    to_type="Identities",
                    attributes={}
                ))
                edges.append(Edge(
                    edge_type="PartOfIdentitiesGraph_Reverse",
                    from_id=hv["id"]["value"],
                    from_type="IdentitiesGraph",
                    to_id=owner_identity["id"]["value"],
                    to_type="Identities",
                    attributes={}
                ))
                edges.append(Edge(
                    edge_type="Hold",
                    from_id=owner_identity["id"]["value"],
                    from_type="Identities",
                    to_id=domain_identity["id"]["value"],
                    to_type="Identities",
                    attributes=ownership
                ))
                edges.append(Edge(
                    edge_type="Resolve",
                    from_id=domain_identity["id"]["value"],
                    from_type="Identities",
                    to_id=owner_identity["id"]["value"],
                    to_type="Identities",
                    attributes=resolve_edge
                ))

                if is_primary and reverse_address:
                    reverse_identity = {
                        "id": {"value": f"{Platform.ethereum.value},{reverse_address}", "op": "ignore_if_exists"},
                        "platform": {"value": Platform.ethereum.value, "op": "ignore_if_exists"},
                        "identity": {"value": reverse_address, "op": "ignore_if_exists"},
                        "updated_at": {"value": updated_at, "op": "max"},
                    }
                    edges.append(Edge(
                        edge_type="Reverse_Resolve",
                        from_id=reverse_identity["id"]["value"],
                        from_type="Identities",
                        to_id=domain_identity["id"]["value"],
                        to_type="Identities",
                        attributes=resolve_edge
                    ))

        # Upsert unstoppabledomains to profile table and graph_id
        async with get_asyncpg_session() as conn:
            await conn.executemany(upsert_sql, upsert_values)
            await conn.executemany(graph_id_upsert_sql, upsert_graph_id_values)
            logging.info("Batch insert unstoppabledomains %s to storage successfully.", domain_unique_ids)

        # # Delete old connections with unstoppabledomains
        # await delete_all_edges_by_source(
        #     [EDGE_PART_OF_IDENTITY_GRAPH, EDGE_HOLD, EDGE_RESOLVE, EDGE_REVERSE_RESOLVE],
        #     domain_unique_ids
        # )
        # logging.info("Delete all unstoppabledomains %s from graphdb successfully.", domain_unique_ids)

        await upsert_graph(vertices, edges)
        logging.info("Upsert all unstoppabledomains from graphdb successfully.")

    except Exception as ex:
        logging.exception(ex)
        return

def filter_unstoppabledomains_query_ids(identities):
    final_query_ids = set()
    cnt = 0
    for identity in identities:
        cnt += 1
        is_evm = is_ethereum_address(identity)
        if is_evm:
            final_query_ids.add(f"{Platform.unstoppabledomains.value},{identity}")
        else:
            if 0 < len(identity) < 256:
                # check postfix
                if identity.find('.') != -1:
                    name_postfix = identity.split('.')[-1]
                    if name_postfix in POSTFIX:
                        final_query_ids.add(f"{Platform.unstoppabledomains.value},{identity}")
                    else:
                        logging.warning("Invalid unstoppabledomains postfix %s", identity)

        if cnt > QUERY_MAX_LIMIT:
            break

    return list(final_query_ids)

async def query_and_update_missing_query_ids(query_ids):
    # logging.debug("query_and_update_missing_query_ids input %s", query_ids)
    domains = await batch_query_domains_from_api(query_ids)
    identity_records = match_unstoppabledomains_profile_records(domains)
    # need cache where query_id is not in storage to avoid frequency access db

    exists_query_ids = []
    if identity_records:
        await save_unstoppabledomains_profile_to_db(domains)
        logging.info("batch_set_unstoppabledomains_to_cache")
        await batch_set_unstoppabledomains_to_cache(identity_records, expire_window=24*3600)
        for record in identity_records:
            exists_query_ids.extend(record.aliases)
            # asyncio.create_task(set_unstoppabledomains_to_cache(record, expire_window=24*3600))
            # await set_unstoppabledomains_to_cache(record, expire_window=24*3600)

    empty_query_ids = list(set(query_ids) - set(exists_query_ids))
    for empty_query_id in empty_query_ids:
        asyncio.create_task(set_empty_unstoppabledomains_profile_to_cache(empty_query_id, {}, expire_window=24*3600))

    return identity_records

async def query_unstoppabledomains_profile_by_ids_cache(info, identities, require_cache=False):
    filter_query_ids = filter_unstoppabledomains_query_ids(identities)
    if len(filter_query_ids) == 0:
        return []

    identity_records = []
    if require_cache is False:
        # query data from api and return immediately
        # saving to db and graphdb
        logging.info("unstoppabledomains filter_input_ids %s", filter_query_ids)
        domains = await batch_query_domains_from_api(filter_query_ids)
        # TODO: try caching batch_query_domains_from_api
        # if api failed, use db `unstoppabledomains` saved old data
        identity_records = match_unstoppabledomains_profile_records(domains)
        await save_unstoppabledomains_profile_to_db(domains)
        # asyncio.create_task(save_unstoppabledomains_profile_to_db(domains))
        return identity_records

    # require_cache is True:
    cache_identity_records, \
    require_update_ids, \
    missing_query_ids = await get_unstoppabledomains_from_cache(filter_query_ids, expire_window=12*3600)

    logging.info("unstoppabledomains input len(filter_query_ids): {}".format(len(filter_query_ids)))
    logging.info("unstoppabledomains input filter_query_ids: {}".format(filter_query_ids))
    logging.debug("unstoppabledomains missing_query_ids: {}".format(missing_query_ids))
    logging.debug("unstoppabledomains require_update_ids: {}".format(require_update_ids))
    logging.debug("unstoppabledomains cache_identity_records: {}".format(len(cache_identity_records)))

    final_identity_records = cache_identity_records.copy()
    if missing_query_ids:
        logging.info("unstoppabledomains missing data {}".format(missing_query_ids))
        missing_identity_records = await query_and_update_missing_query_ids(missing_query_ids)
        final_identity_records.extend(missing_identity_records)

    if require_update_ids:
        logging.info("unstoppabledomains has olddata and return immediately {}".format(require_update_ids))
        # Update background
        asyncio.create_task(query_and_update_missing_query_ids(require_update_ids))

    return final_identity_records
