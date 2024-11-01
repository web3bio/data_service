#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-09-06 15:40:40
LastEditors: Zella Zhong
LastEditTime: 2024-11-01 12:36:08
FilePath: /data_service/src/resolver/basenames.py
Description: 
'''
import asyncio
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

from session import get_session
from model import BasenameModel
from cache.redis import RedisClient

from utils import check_evm_address, convert_camel_case, compute_namehash_nowrapped
from utils.address import is_ethereum_address, is_base58_solana_address
from utils.timeutils import get_unix_microseconds, parse_time_string, get_current_time_string

from scalar.platform import Platform
from scalar.network import Network, Address, CoinTypeMap
from scalar.identity_graph import IdentityRecordSimplified
from scalar.identity_record import IdentityRecord
from scalar.profile import Profile, SocialProfile
from scalar.error import DomainNotFound, EmptyInput, EvmAddressInvalid, ExceedRangeInput
from scalar.type_convert import strawberry_type_to_jsonstr

QUERY_MAX_LIMIT = 200


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


def get_basenames_selected_fields(db_baseclass_name, info):
    attr_names = [c_attr.key for c_attr in inspect(db_baseclass_name).mapper.column_attrs]
    # Extract selected fields from the `info` object
    base_selected_fields = ["namenode", "name", "owner", "resolved_address", "is_primary", "reverse_address"]
    filter_selected_fields = []
    filter_selected_fields.extend(base_selected_fields)
    info_selected_fields = info.selected_fields[0].selections

    for field in info_selected_fields:
        field_name = convert_camel_case(field.name)
        match field_name:
            case "id":
                continue
            case "identity":
                filter_selected_fields.append("name")
            case "platform":
                continue
            case "network":
                continue
            case "primary_name":
                filter_selected_fields.append("name")
            case "is_primary":
                filter_selected_fields.append("is_primary")
            case "resolved_address":
                filter_selected_fields.append("resolved_address")
            case "owner_address":
                filter_selected_fields.append("owner")
            case "expired_at":
                filter_selected_fields.append("expire_time")
            case "profile":
                profile_selected_fields = get_selected_fields("profile", info_selected_fields)
                if profile_selected_fields:
                    for profile_field in profile_selected_fields:
                        profile_field_name = convert_camel_case(profile_field.name)
                        match profile_field_name:
                            case "identity":
                                filter_selected_fields.append("name")
                            case "platform":
                                continue
                            case "address":
                                filter_selected_fields.append("resolved_address")
                            case "display_name":
                                filter_selected_fields.append("name")
                                filter_selected_fields.append("texts")
                            case "avatar":
                                continue
                            case "description":
                                continue
                            case "contenthash":
                                filter_selected_fields.append("contenthash")
                            case "texts":
                                filter_selected_fields.append("texts")
                            case "addresses":
                                filter_selected_fields.append("resolved_records")
            case "graph_id":
                continue
            case "edges":
                continue
            case "vertices":
                identity_graph_fields = get_selected_fields("vertices", info_selected_fields)
                if identity_graph_fields:
                    for graph_field in identity_graph_fields:
                        graph_field_name = convert_camel_case(graph_field.name)
                        match graph_field_name:
                            case "id":
                                continue
                            case "identity":
                                filter_selected_fields.append("name")
                            case "platform":
                                continue
                            case "network":
                                continue
                            case "primary_name":
                                filter_selected_fields.append("name")
                            case "is_primary":
                                filter_selected_fields.append("is_primary")
                            case "resolved_address":
                                filter_selected_fields.append("resolved_address")
                            case "owner_address":
                                filter_selected_fields.append("owner")
                            case "expired_at":
                                filter_selected_fields.append("expire_time")
                            case "profile":
                                profile_selected_fields = get_selected_fields("profile", info_selected_fields)
                                if profile_selected_fields:
                                    for profile_field in profile_selected_fields:
                                        profile_field_name = convert_camel_case(profile_field.name)
                                        match profile_field_name:
                                            case "identity":
                                                filter_selected_fields.append("name")
                                            case "platform":
                                                continue
                                            case "address":
                                                filter_selected_fields.append("resolved_address")
                                            case "display_name":
                                                filter_selected_fields.append("name")
                                                filter_selected_fields.append("texts")
                                            case "avatar":
                                                continue
                                            case "description":
                                                continue
                                            case "contenthash":
                                                filter_selected_fields.append("contenthash")
                                            case "texts":
                                                filter_selected_fields.append("texts")
                                            case "addresses":
                                                filter_selected_fields.append("resolved_records")
            # If an exact match is not confirmed, this last case will be used if provided
            case _:
                continue

    match_selected_fields = list(set(attr_names) & set(filter_selected_fields))
    # logging.info("Match selected fields: %s", match_selected_fields)
    match_selected_fields = [getattr(db_baseclass_name, f) for f in match_selected_fields]
    return match_selected_fields


async def query_profile_by_single_basenames(info, name):
    if not name.endswith('base.eth'):
        return None

    selected_fields = get_basenames_selected_fields(BasenameModel, info)

    async with get_session() as s:
        sql = select(BasenameModel).options(load_only(*selected_fields)) \
            .filter(BasenameModel.name == name)
        result = await s.execute(sql)
        db_result = result.scalars().one_or_none()

    if db_result is None:
        return None

    profile_record = {key: value for key, value in db_result.__dict__.items()}
    name = profile_record.get('name', None)
    if name is None:
        return None

    resolved_addresses = []
    owner_addresses = []
    owner = profile_record.get('owner', None)

    if owner is not None:
        owner_addresses.append(Address(network=Network.ethereum, address=owner))

    network = None
    address = None
    resolved_address = profile_record.get('resolved_address', None)
    if resolved_address is not None:
        address = resolved_address
        network = Network.ethereum
        resolved_addresses.append(Address(network=network, address=resolved_address))
    else:
        address = owner
        network = Network.ethereum

    display_name = name
    avatar = None
    description = None
    texts = profile_record.get('texts', {})
    if texts:
        # Filter out empty strings and decode non-empty texts
        process_texts = {key: unquote(text, 'utf-8') for key, text in texts.items() if text != ""}
        avatar = process_texts.get("avatar", None)
        description = process_texts.get("description", None)
        display_name = process_texts.get("name", name)
        texts = process_texts

    if not texts:
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
        contenthash=profile_record.get('contenthash', None),
        texts=texts,
        addresses=records,
        social=None
    )

    identity_record = IdentityRecord(
        id=f"{Platform.basenames.value},{name}",
        identity=name,
        platform=Platform.basenames,
        network=Network.ethereum,
        primary_name=None,
        is_primary=profile_record.get('is_primary', False),
        owner_address=owner_addresses,
        resolved_address=resolved_addresses,
        expired_at=profile_record.get('expire_time', None),
        profile=profile
    )
    return identity_record


async def query_profile_by_basenames(info, names):
    if len(names) > QUERY_MAX_LIMIT:
        return ExceedRangeInput(QUERY_MAX_LIMIT)

    logging.debug("query_profile_by_basenames %s", names)
    checked_names = []
    for name in names:
        if name.endswith("base.eth"):
            checked_names.append(name)

    selected_fields = get_basenames_selected_fields(BasenameModel, info)
    db_dict = {}
    async with get_session() as s:
        sql = select(BasenameModel).options(load_only(*selected_fields)) \
            .filter(BasenameModel.name.in_(checked_names))
        result = await s.execute(sql)
        db_records = result.scalars().all()
        for row in db_records:
            db_dict[row.namenode] = {key: value for key, value in row.__dict__.items()}

    result = []
    for namenode, profile_record in db_dict.items():
        if profile_record is not None:
            name = profile_record.get('name', None)
            if name is None:
                continue

            resolved_addresses = []
            owner_addresses = []
            owner = profile_record.get('owner', None)
            if owner is not None:
                owner_addresses.append(Address(network=Network.ethereum, address=owner))

            network = None
            address = None
            resolved_address = profile_record.get('resolved_address', None)
            if resolved_address is not None:
                address = resolved_address
                network = Network.ethereum
                resolved_addresses.append(Address(network=network, address=resolved_address))
            else:
                address = owner
                network = Network.ethereum

            display_name = name
            avatar = None
            description = None
            texts = profile_record.get('texts', {})
            if texts:
                # Filter out empty strings and decode non-empty texts
                process_texts = {key: unquote(text, 'utf-8') for key, text in texts.items() if text != ""}
                avatar = process_texts.get("avatar", None)
                description = process_texts.get("description", None)
                display_name = process_texts.get("name", name)
                texts = process_texts

            if not texts:
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
                contenthash=profile_record.get('contenthash', None),
                texts=texts,
                addresses=records,
                social=None
            )

            result.append(IdentityRecordSimplified(
                id=f"{Platform.basenames.value},{name}",
                identity=name,
                platform=Platform.basenames,
                network=Network.ethereum,
                primary_name=None,
                owner_address=owner_addresses,
                resolved_address=resolved_addresses,
                is_primary=profile_record.get('is_primary', False),
                expired_at=profile_record.get('expire_time', None),
                profile=profile
            ))
    return result

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

async def set_basenames_empty_profile_to_cache(query_id, empty_record, expire_window):
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

async def batch_set_basenames_profile_to_cache(
    cache_identity_records: typing.List[IdentityRecordSimplified], expire_window: int
):
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
        await redis_client.eval(lua_script, len(keys_with_expiration), *keys_with_expiration, final_expire_window)

    logging.info("ensname batch set profiles and aliases successfully, with expirations [%s]", list(profile_data.keys()))

def get_basenames_fields():
    '''
    description: retrieve all fields
    return {*}
    '''
    # Get all fields for each model using reflection
    profile_fields = [getattr(BasenameModel, c.key) for c in inspect(BasenameModel).mapper.column_attrs]
    return profile_fields

async def batch_query_profile_by_basenames_db(query_ids) -> typing.List[IdentityRecordSimplified]:
    address_list = set()
    name_list = set()
    for _id in query_ids:
        identity = _id.split(",")[1]
        is_evm = is_ethereum_address(identity)
        if is_evm:
            address_list.add(identity)
        else:
            name_list.add(identity)

    checked_addresses = list(address_list)
    checked_names = list(name_list)

    profile_fields = get_basenames_fields()
    profile_dict = {}
    async with get_session() as s:
        if checked_names:
            sql = select(BasenameModel).options(load_only(*profile_fields)) \
                .filter(BasenameModel.name.in_(checked_names))
            result = await s.execute(sql)
            db_records = result.scalars().all()
            for row in db_records:
                profile_dict[row.namenode] = row
        
        if checked_addresses:
            sql = select(BasenameModel).options(load_only(*profile_fields)) \
                .filter(BasenameModel.reverse_address.in_(checked_addresses))
            result = await s.execute(sql)
            db_records = result.scalars().all()
            for row in db_records:
                if row.name.endswith("base.eth"):
                    profile_dict[row.namenode] = row

    result = []
    for namenode in profile_dict:
        profile_record: BasenameModel = profile_dict.get(namenode, None)
        if profile_record is not None:
            name = profile_record.name
            if name is None:
                continue
            
            basenames_primary_id = f"{Platform.basenames.value},{name}"
            aliases = [basenames_primary_id]
            resolved_addresses = []
            owner_addresses = []
            owner = profile_record.owner
            if owner is not None:
                owner_addresses.append(Address(network=Network.ethereum, address=owner))

            network = None
            address = None
            is_primary = profile_record.is_primary
            reverse_address = profile_record.reverse_address
            if is_primary and reverse_address:
                aliases.append(f"{Platform.basenames.value},{reverse_address}")
            resolved_address = profile_record.resolved_address
            if resolved_address is not None:
                address = resolved_address
                network = Network.ethereum
                resolved_addresses.append(Address(network=network, address=resolved_address))
            else:
                address = owner
                network = Network.ethereum

            display_name = name
            avatar = None
            description = None
            texts = profile_record.texts
            if texts:
                # Filter out empty strings and decode non-empty texts
                process_texts = {key: unquote(text, 'utf-8') for key, text in texts.items() if text != ""}
                avatar = process_texts.get("avatar", None)
                description = process_texts.get("description", None)
                display_name = process_texts.get("name", name)
                texts = process_texts

            if not texts:
                texts = None

            resolved_records = profile_record.resolved_records
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
                contenthash=profile_record.contenthash,
                texts=texts,
                addresses=records,
                social=None
            )

            result.append(IdentityRecordSimplified(
                id=basenames_primary_id,
                aliases=aliases,
                identity=name,
                platform=Platform.basenames,
                network=Network.ethereum,
                primary_name=None,
                owner_address=owner_addresses,
                resolved_address=resolved_addresses,
                is_primary=is_primary,
                expired_at=profile_record.expire_time,
                profile=profile
            ))
    return result

async def batch_get_basenames_profile_from_cache(query_ids, expire_window):
    '''
    description: 
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

async def query_and_update_missing_query_ids(query_ids):
    # logging.debug("query_and_update_missing_query_ids input %s", query_ids)
    identity_records = await batch_query_profile_by_basenames_db(query_ids)
    # need cache where query_id is not in storage to avoid frequency access db

    exists_query_ids = []
    if identity_records:
        asyncio.create_task(batch_set_basenames_profile_to_cache(identity_records, expire_window=24*3600))

    for record in identity_records:
        exists_query_ids.extend(record.aliases)
        # asyncio.create_task(set_ensname_profile_to_cache(record, expire_window=24*3600))

    empty_query_ids = list(set(query_ids) - set(exists_query_ids))
    for empty_query_id in empty_query_ids:
        asyncio.create_task(set_basenames_empty_profile_to_cache(empty_query_id, {}, expire_window=24*3600))

    return identity_records

def filter_basenames_query_ids(identities):
    final_query_ids = set()
    cnt = 0
    for identity in identities:
        cnt += 1
        is_evm = is_ethereum_address(identity)
        if is_evm:
            final_query_ids.add(f"{Platform.basenames.value},{identity}")
        else:
            if 0 < len(identity) < 256:
                # check postfix
                if identity.find('.') != -1:
                    final_query_ids.add(f"{Platform.basenames.value},{identity}")

        if cnt > QUERY_MAX_LIMIT:
            break

    return list(final_query_ids)

async def query_basenames_profile_by_ids_cache(info, identities, require_cache=False):
    # if len(identities) > QUERY_MAX_LIMIT:
    #     return ExceedRangeInput(QUERY_MAX_LIMIT)
    # TODO: add limit offset for pagination

    filter_query_ids = filter_basenames_query_ids(identities)
    if len(filter_query_ids) == 0:
        return []

    identity_records = []
    if require_cache is False:
        # query data from db and return immediately
        logging.info("batch query ensname input %s", filter_query_ids)
        identity_records = await batch_query_profile_by_basenames_db(filter_query_ids)
        return identity_records

    # require_cache is True:
    cache_identity_records, \
    require_update_ids, \
    missing_query_ids = await batch_get_basenames_profile_from_cache(filter_query_ids, expire_window=12*3600)

    logging.info("ensname input filter_query_ids: {}".format(filter_query_ids))
    # logging.debug("ensname missing_query_ids: {}".format(missing_query_ids))
    # logging.debug("ensname require_update_ids: {}".format(require_update_ids))
    # logging.debug("ensname cache_identity_records: {}".format(len(cache_identity_records)))

    final_identity_records = cache_identity_records.copy()
    if missing_query_ids:
        logging.info("ensname missing data {}".format(missing_query_ids))
        missing_identity_records = await query_and_update_missing_query_ids(missing_query_ids)
        final_identity_records.extend(missing_identity_records)

    if require_update_ids:
        logging.info("ensname has olddata and return immediately {}".format(require_update_ids))
        # Update background
        asyncio.create_task(query_and_update_missing_query_ids(require_update_ids))

    return final_identity_records