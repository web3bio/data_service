#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-24 17:34:05
LastEditors: Zella Zhong
LastEditTime: 2024-10-25 18:57:27
FilePath: /data_service/src/resolver/unstoppabledomains.py
Description: 
'''
import asyncio
import ssl
import certifi
import time
import random
import logging
import aiohttp
import json

import strawberry

from datetime import datetime, timedelta
from sqlalchemy.inspection import inspect
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import load_only
from urllib.parse import unquote

from session import get_session
from model.unstoppabledomains import UnstoppabledomainsModel

from cache.redis import RedisClient

import setting
from utils import check_evm_address, convert_camel_case, uint256_to_bytes32
from utils.timeutils import get_unix_microseconds, get_current_time_string, parse_time_string

from scalar.platform import Platform
from scalar.network import Network, Address, CoinTypeMap
from scalar.identity_graph import IdentityRecordSimplified
from scalar.identity_record import IdentityRecord
from scalar.profile import Profile
from scalar.error import DomainNotFound, EmptyInput, EvmAddressInvalid, ExceedRangeInput
from scalar.type_convert import strawberry_type_to_jsonstr

def get_selected_fields(field_name: str, selected_fields):
    """
    Recursively find and return the selected fields for a specific field name.
    :param field_name: The name of the field to search for (e.g., 'profile').
    :param selected_fields: The list of selected fields in the GraphQL query.
    :return: List of subfields for the given field name or None if not found.
    """
    for field in selected_fields:
        if field.name == field_name:
            return field.selections  # Return the nested selections of the field
        if field.selections:
            # Recursively search through the subfields
            subfield = get_selected_fields(field_name, field.selections)
            if subfield:
                return subfield
    return None  # Explicitly return None if the field is not found


def get_unstoppabledomains_selected_fields(db_baseclass_name, info):
    return []


async def get_unstoppabledomain_from_cache(primary_id, expire_window):
    '''
    description: get data from cache and determine if an update is required
        primary_id: "platform,identity", # e.g., "unstoppabledomains,0xzella.crypto"
        expire_window: e.g., 4 hours would be 4 * 3600 = 14400 seconds
    return cache_value, cache_required_update
    '''
    cache_key = f"profile:{primary_id}"  # e.g., "profile:unstoppabledomains,0xzella.crypto"

    # Fetching from Redis using the actual Redis client
    redis_client = await RedisClient.get_instance()
    # Fetch the cache from Redis
    cache_value = await redis_client.get(cache_key)

    if cache_value is None:
        # If the cache key doesn't exist, mark it for an update
        logging.debug(f"Cache miss for key: {cache_key}. Data needs to be fetched.")
        return None, True  # No data found, and an update is needed

    # Deserialize the cache value (stored as a JSON string)
    cache_value_dict = json.loads(cache_value)

    updated_at = cache_value_dict.get("updated_at", None)
    if not updated_at:
        logging.warning(f"Cache key {cache_key} is missing 'updated_at'. Marking for update.")
        return None, True

    # Convert 'updated_at' from string to datetime object
    updated_at_datetime = parse_time_string(updated_at)

    # Get current time
    now = datetime.now()

    # Check if the cache needs to be updated based on the expiration window (in seconds)
    if now - updated_at_datetime > timedelta(seconds=expire_window):
        logging.debug(f"Cache key {cache_key} is expired. Returning old data, but marking for update.")
        if len(cache_value_dict) == 1:
            # only have one field(updated_at) is also not exist
            return None, True
        return cache_value_dict, True  # Old data is returned, but it needs to be updated

    if len(cache_value_dict) == 1:
        # only have one field(updated_at) is also not exist
        return None, False

    logging.debug(f"Cache key {cache_key} is fresh. Returning data.")
    return cache_value_dict, False  # Cache is fresh, no need for update


async def set_unstoppabledomain_to_cache(primary_id, cache_identity_record, expire_window):
    '''
    description: set data into the cache with a Redis lock to prevent concurrency issues
        primary_id: "platform,identity", # e.g., "unstoppabledomains,0xzella.crypto"
        expire_window: e.g., 4 hours would be 4 * 3600 = 14400 seconds
        expire_window may longer that 4 hours and add some random seconds to avoid batch key expiration issues
    return {*}
    '''

    cache_key = f"profile:{primary_id}"  # e.g., "profile:unstoppabledomains,0xzella.crypto"
    lock_key = f"{cache_key}.lock"

    # Generate a unique value for the lock
    unique_value = "{}:{}".format(cache_key, get_unix_microseconds())
    random_offset = random.randint(0, 30 * 60)  # Adding up to 30 minutes of randomness
    final_expire_window = expire_window + random_offset

    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(lock_key, unique_value, lock_timeout=30):
            logging.debug(f"Lock acquired for key: {lock_key}")

            cache_value_json = "{}"
            if cache_identity_record is None:
                updated_at = get_current_time_string()
                cache_value_json = json.dumps({"updated_at": updated_at})
            else:
                # Set the current time as 'updated_at' in "yyyy-mm-dd HH:MM:SS" format
                cache_identity_record.updated_at = datetime.now()
                cache_value_json = strawberry_type_to_jsonstr(cache_identity_record)  # Serialize the cache value
            # Set the cache in Redis with the specified expiration time (in seconds)
            redis_client = await RedisClient.get_instance()
            await redis_client.set(cache_key, cache_value_json, ex=final_expire_window)
            logging.debug(f"Cache updated for key: {cache_key}")
        else:
            logging.warning(f"Could not acquire lock for key: {lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(lock_key, unique_value)
        logging.debug(f"Lock released for key: {lock_key}")


def get_unstoppabledomain_from_db():
    pass

def set_unstoppabledomain_to_db():
    pass

def update_graphdb():
    pass


async def query_single_profile_and_update_immediately(name, require_cache=False):
    # Fetch data and return immediately
    identity_record = await get_identity_record_by_name(name)
    if require_cache is True:
        primary_id = "{},{}".format(Platform.unstoppabledomains.value, name)
        # Update cache asynchronously in the background
        asyncio.create_task(set_unstoppabledomain_to_cache(primary_id, identity_record, expire_window=120))
        return identity_record
    else:
        return identity_record

async def query_profile_by_single_unstoppabledomain(info, name):
    primary_id = "{},{}".format(Platform.unstoppabledomains.value, name)
    cache_value, cache_required_update = await get_unstoppabledomain_from_cache(primary_id, expire_window=30)
    if cache_value is None:
        identity_record = await query_single_profile_and_update_immediately(name, require_cache=True)
        logging.info("no history return immediately")
        return identity_record
    elif cache_value is not None:
        # Match IdentityRecord
        if cache_required_update is True:
            logging.info("has olddata and cache_required_update")
            asyncio.create_task(query_single_profile_and_update_immediately(name, require_cache=True))

        identity_record = cache_value_decode_identity_record(cache_value)
        logging.info("has olddata return immediately")
        return identity_record


async def query_profile_by_unstoppabledomains(info, names):
    selected_fields = get_unstoppabledomains_selected_fields(UnstoppabledomainsModel, info)


async def query_profile_by_owner_addresses(info, owners):
    selected_fields = get_unstoppabledomains_selected_fields(UnstoppabledomainsModel, info)


def cache_value_decode_identity_record(cache_value):
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
                social=profile_data.get("social")
            )
        
        expired_at_str = cache_value.get("expired_at")
        updated_at_str = cache_value.get("updated_at")

        expired_at = datetime.strptime(expired_at_str, "%Y-%m-%d %H:%M:%S") if expired_at_str else None
        updated_at = datetime.strptime(updated_at_str, "%Y-%m-%d %H:%M:%S") if updated_at_str else None

        # Return the IdentityRecord instance
        return IdentityRecord(
            id=cache_value.get("id"),
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

async def get_identity_record_by_name(domain_name):
    try:
        profile_records = await get_domains_by_name(domain_name)
        if len(profile_records) == 0:
            return None

        profile_record = profile_records[0]

        name = profile_record.get('name', None)
        resolved_addresses = []
        owner_addresses = []
        owner = profile_record.get('owner', None)
        if owner is not None:
            owner_addresses.append(Address(network=Network.ethereum, address=owner))

        network = Network.ethereum
        address = None
        resolved_address = profile_record.get('resolved_address', None)
        if resolved_address is not None:
            address = resolved_address
            network = Network.ethereum
            resolved_addresses.append(Address(network=network, address=resolved_address))
        else:
            address = owner
            network = Network.ethereum

        # TODO: unstoppabledomains records:
        # crypto.* — Records related to crypto payments
        # dns.* — DNS records
        # dweb.* — Records related to distributed content network protocols
        # browser.* — Hint records for web browsers
        display_name = name
        avatar = None
        description = None
        texts = profile_record.get('texts', {})
        if texts:
            # texts = {key: unquote(text, 'utf-8') for key, text in texts.items()}
            avatar = texts.get("avatar", None)
            description = texts.get("description", None)
            display_name = texts.get("name", name)
        else:
            texts = None

        resolved_records = profile_record.get('resolved_records', {})
        records = []
        if resolved_records:
            for coin_type, addr in resolved_records.items():
                if coin_type in CoinTypeMap:
                    if addr != "0x":
                        records.append(Address(network=CoinTypeMap[coin_type], address=addr))

        profile = Profile(
            uid=None,
            identity=name,
            platform=Platform.basenames,
            network=network,
            address=address,
            display_name=display_name,
            avatar=avatar,
            description=description,
            contenthash=None,
            texts=texts,
            addresses=records,
            social=None
        )
        identity_record = IdentityRecord(
            id=f"{Platform.unstoppabledomains.value},{name}",
            identity=name,
            platform=Platform.unstoppabledomains,
            network=network,
            primary_name=None,
            is_primary=profile_record.get('is_primary', False),
            owner_address=owner_addresses,
            resolved_address=resolved_addresses,
            expired_at=profile_record.get('expire_time', None),
            updated_at=profile_record.get('update_time', None),
            profile=profile,
        )
        return identity_record
    except Exception as ex:
        logging.exception(ex)
        return None


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
    logging.info("unstoppabledomains get_domains_by_name %s", query_url)

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
                if name is not None and namenode is not None:
                    reverse_address = None
                    owner = metadata.get("owner", None)
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
    # 30 * 100 perPage = 3000, maxlimit
    while(hasMore):
        query_url = "{}/resolve/domains?owners={}".format(
            setting.UPSTREAM["unstoppabledomains_api"]["api"],
            owner_address
        )
        if nextStartingAfter is not None:
            query_url = "{}&startingAfter={}".format(query_url, nextStartingAfter)

        logging.info("unstoppabledomains get_domains_by_owner %s", query_url)

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
                

                cnt += 1
                page_meta = res.get("meta", None)
                if page_meta is not None:
                    hasMore = page_meta.get("hasMore", False)
                    nextStartingAfter = page_meta.get("nextStartingAfter", None)
                else:
                    hasMore = False
                    nextStartingAfter = None
                    break

                res_data = res.get("data", [])
                if len(res_data) == 0:
                    hasMore = False
                    nextStartingAfter = None
                    break

                if cnt > 30:
                    break

                for item in res_data:
                    attributes = item.get("attributes", None)
                    if attributes is not None:
                        metadata = attributes.get("meta", None)
                        if metadata is not None:
                            name = metadata.get("domain", None)
                            namenode = metadata.get("namehash", None)
                            if name is not None and namenode is not None:
                                reverse_address = None
                                owner = metadata.get("owner", None)
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

    return domains
