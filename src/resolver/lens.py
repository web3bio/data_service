#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-07 01:31:36
LastEditors: Zella Zhong
LastEditTime: 2024-10-30 15:08:13
FilePath: /data_service/src/resolver/lens.py
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
from model.lens import LensV2Profile, LensV2Social
from cache.redis import RedisClient

from utils import convert_camel_case
from utils.address import is_ethereum_address, is_base58_solana_address
from utils.timeutils import get_unix_microseconds, parse_time_string, get_current_time_string

from scalar.platform import Platform
from scalar.network import Network, Address, CoinTypeMap
from scalar.identity_graph import IdentityRecordSimplified
from scalar.identity_record import IdentityRecord
from scalar.profile import Profile, SocialProfile
from scalar.error import EmptyInput, ExceedRangeInput
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

def get_lens_selected_fields(info):
    info_selected_fields = info.selected_fields[0].selections
    profile_fields = ["profile_id", "name", "is_primary", "address"]
    social_fields = []
    for field in info_selected_fields:
        field_name = convert_camel_case(field.name)
        match field_name:
            case "id":
                continue
            case "identity":
                profile_fields.append("profile_id")
                profile_fields.append("name")
            case "platform":
                continue
            case "network":
                continue
            case "primary_name":
                profile_fields.append("name")
            case "is_primary":
                profile_fields.append("is_primary")
            case "resolved_address":
                profile_fields.append("address")
            case "owner_address":
                profile_fields.append("address")
            case "expired_at":
                continue
            case "profile":
                profile_selected_fields = get_selected_fields("profile", info_selected_fields)
                if profile_selected_fields:
                    for profile_field in profile_selected_fields:
                        profile_field_name = convert_camel_case(profile_field.name)
                        match profile_field_name:
                            case "identity":
                                profile_fields.append("name")
                            case "platform":
                                continue
                            case "address":
                                profile_fields.append("address")
                            case "avatar":
                                profile_fields.append("avatar")
                            case "display_name":
                                profile_fields.append("display_name")
                            case "description":
                                profile_fields.append("description")
                            case "cover_picture":
                                profile_fields.append("cover_picture")
                            case "contenthash":
                                continue
                            case "texts":
                                profile_fields.append("texts")
                            case "addresses":
                                profile_fields.append("address")
                            case "social":
                                social_selected_fields = get_selected_fields("social", profile_selected_fields)
                                if social_selected_fields:
                                    for social_field in social_selected_fields:
                                        social_field_name = convert_camel_case(social_field.name)
                                        match social_field_name:
                                            case "uid":
                                                social_fields.append("fid")
                                            case "following":
                                                social_fields.append("following")
                                            case "follower":
                                                social_fields.append("follower")
                                            case "updated_at":
                                                social_fields.append("update_time")
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
                                profile_fields.append("profile_id")
                                profile_fields.append("name")
                            case "platform":
                                continue
                            case "network":
                                continue
                            case "primary_name":
                                profile_fields.append("name")
                            case "is_primary":
                                profile_fields.append("is_primary")
                            case "resolved_address":
                                profile_fields.append("address")
                            case "owner_address":
                                profile_fields.append("address")
                            case "expired_at":
                                continue
                            case "profile":
                                profile_selected_fields = get_selected_fields("profile", info_selected_fields)
                                if profile_selected_fields:
                                    for profile_field in profile_selected_fields:
                                        profile_field_name = convert_camel_case(profile_field.name)
                                        match profile_field_name:
                                            case "identity":
                                                profile_fields.append("name")
                                            case "platform":
                                                continue
                                            case "address":
                                                profile_fields.append("address")
                                            case "avatar":
                                                profile_fields.append("avatar")
                                            case "display_name":
                                                profile_fields.append("display_name")
                                            case "description":
                                                profile_fields.append("description")
                                            case "cover_picture":
                                                profile_fields.append("cover_picture")
                                            case "contenthash":
                                                continue
                                            case "texts":
                                                profile_fields.append("texts")
                                            case "addresses":
                                                profile_fields.append("address")
                                            case "social":
                                                social_selected_fields = get_selected_fields("social", profile_selected_fields)
                                                if social_selected_fields:
                                                    for social_field in social_selected_fields:
                                                        social_field_name = convert_camel_case(social_field.name)
                                                        match social_field_name:
                                                            case "uid":
                                                                social_fields.append("fid")
                                                            case "following":
                                                                social_fields.append("following")
                                                            case "follower":
                                                                social_fields.append("follower")
                                                            case "updated_at":
                                                                social_fields.append("update_time")
            case _:
                continue

    profile_fields = list(
        set([c_attr.key for c_attr in inspect(LensV2Profile).mapper.column_attrs]) \
        & set(profile_fields))
    social_fields = list(
        set([c_attr.key for c_attr in inspect(LensV2Social).mapper.column_attrs]) \
        & set(social_fields))
    # logging.info("Match profile_fields: %s", profile_fields)
    # logging.info("Match social_fields: %s", social_fields)

    profile_fields = [getattr(LensV2Profile, f) for f in profile_fields]
    social_fields = [getattr(LensV2Social, f) for f in social_fields]
    return profile_fields, social_fields


async def query_profile_by_single_lens_handle(info, name):
    profile_fields,\
    social_fields = get_lens_selected_fields(info)

    profile_record = None
    profile_id = None
    social_record = None
    async with get_session() as s:
        if len(profile_fields) > 0:
            profile_sql = select(LensV2Profile).options(
                load_only(*profile_fields))\
                .filter(LensV2Profile.name == name)
            profile_result = await s.execute(profile_sql)
            one_profile_record = profile_result.scalars().one_or_none()
            if one_profile_record is not None:
                profile_id = one_profile_record.profile_id
                profile_record = {key: value for key, value in one_profile_record.__dict__.items()}

        if len(social_fields) > 0:
            if profile_id is not None:
                social_sql = select(LensV2Social).options(
                    load_only(*social_fields))\
                    .filter(LensV2Social.profile_id == profile_id)
                social_result = await s.execute(social_sql)
                one_social_record = social_result.scalars().one_or_none()
                if one_social_record is not None:
                    social_record = {key: value for key, value in one_social_record.__dict__.items()}

    if profile_record is None:
        return None
    if profile_id is None:
        return None

    name = profile_record.get('name', None)
    if name is None:
        return None
    
    aliases = []
    aliases.append("{},#{}".format(Platform.lens.value, profile_id))
    aliases.append("{},{}".format(Platform.lens.value, name))

    network = None
    resolved_address = []
    owner_address = []
    records = []
    address = profile_record.get('address', None)
    if address is not None:
        network = Network.ethereum
        resolved_address.append(Address(address=address, network=network))
        owner_address.append(Address(address=address, network=network))
        records.append(Address(address=address, network=network))
        aliases.append("{},{}".format(Platform.lens.value, address))

    texts = profile_record.get('texts', {})
    if texts:
        # Filter out empty strings and decode non-empty texts
        process_texts = {key: unquote(text, 'utf-8') for key, text in texts.items() if text != ""}
        texts = process_texts

    if not texts:
        texts = None

    cover_picture = profile_record.get('cover_picture', None)
    if cover_picture is not None:
        if texts is not None:
            texts["header"] = cover_picture
        else:
            texts = {"header": cover_picture}

    profile = Profile(
        uid=profile_id,
        identity=name,
        platform=Platform.lens,
        network=network,
        address=address,
        display_name=profile_record.get('display_name', None),
        avatar=profile_record.get('avatar', None),
        description=profile_record.get('description', None),
        texts=texts,
        addresses=records,
        social=None,
    )
    if social_record:
        social = SocialProfile(
            uid=profile_id,
            following=social_record.get('following', 0),
            follower=social_record.get('follower', 0),
            updated_at=social_record.get('update_time', None),
        )
        profile.social = social

    identity_record = IdentityRecord(
        id=f"{Platform.lens.value},{name}",
        identity=name,
        platform=Platform.lens,
        network=network,
        primary_name=None,
        is_primary=profile_record.get('is_primary', False),
        expired_at=None,
        resolved_address=resolved_address,
        owner_address=owner_address,
        profile=profile
    )
    return identity_record

async def query_profile_by_lens_handle(info, names):
    # if len(names) == 0:
    #     return EmptyInput()

    if len(names) > QUERY_MAX_LIMIT:
        return ExceedRangeInput(QUERY_MAX_LIMIT)

    # logging.debug("query_profile_by_lens_handle %s", names)
    profile_fields,\
    social_fields = get_lens_selected_fields(info)

    profile_dict = {}
    profile_ids = []
    social_dict = {}
    async with get_session() as s:
        if len(profile_fields) > 0:
            profile_sql = select(LensV2Profile).options(
                load_only(*profile_fields))\
                .filter(LensV2Profile.name.in_(names))
            profile_result = await s.execute(profile_sql)
            profile_records = profile_result.scalars().all()
            for row in profile_records:
                profile_ids.append(row.profile_id)
                profile_dict[row.profile_id] = {key: value for key, value in row.__dict__.items()}

        if len(social_fields) > 0:
            social_sql = select(LensV2Social).options(
                load_only(*social_fields))\
                .filter(LensV2Social.profile_id.in_(profile_ids))
            social_result = await s.execute(social_sql)
            social_records = social_result.scalars().all()
            for row in social_records:
                social_dict[row.profile_id] = {key: value for key, value in row.__dict__.items()}

    result = []
    for profile_id in profile_ids:
        profile_record = profile_dict.get(profile_id, None)
        network = None
        resolved_addresses = []
        owner_addresses = []
        records = []
        address = profile_record.get('address', None)
        if address is not None:
            network = Network.ethereum
            resolved_addresses.append(Address(address=address, network=network))
            owner_addresses.append(Address(address=address, network=network))
            records.append(Address(address=address, network=network))

        name = profile_record.get('name', None)
        if name is None:
            continue

        texts = profile_record.get('texts', {})
        if texts:
            # Filter out empty strings and decode non-empty texts
            process_texts = {key: unquote(text, 'utf-8') for key, text in texts.items() if text != ""}
            texts = process_texts

        if not texts:
            texts = None

        cover_picture = profile_record.get('cover_picture', None)
        if cover_picture is not None:
            if texts is not None:
                texts["header"] = cover_picture
            else:
                texts = {"header": cover_picture}

        social = None
        if profile_record is not None:
            profile = Profile(
                uid=profile_id,
                identity=name,
                platform=Platform.lens,
                network=network,
                address=address,
                display_name=profile_record.get('display_name', None),
                avatar=profile_record.get('avatar', None),
                description=profile_record.get('description', None),
                texts=texts,
                addresses=records,
                social=None,
            )
            if social_dict:
                social_info = social_dict.get(profile_id, None)
                if social_info:
                    social = SocialProfile(
                        uid=profile_id,
                        following=social_info.get('following', 0),
                        follower=social_info.get('follower', 0),
                        updated_at=social_info.get('update_time', None),
                    )
                    profile.social = social

            result.append(IdentityRecordSimplified(
                id=f"{Platform.lens.value},{name}",
                identity=name,
                platform=Platform.lens,
                network=network,
                primary_name=None,
                is_primary=profile_record.get('is_primary', False),
                expired_at=None,
                resolved_address=resolved_addresses,
                owner_address=owner_addresses,
                profile=profile
            ))

    return result


def get_lens_fields():
    '''
    description: retrieve all fields
    return {*}
    '''    
    # Get all fields for each model using reflection
    profile_fields = [getattr(LensV2Profile, c.key) for c in inspect(LensV2Profile).mapper.column_attrs]
    social_fields = [getattr(LensV2Social, c.key) for c in inspect(LensV2Social).mapper.column_attrs]

    return profile_fields, social_fields

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

async def get_lens_profile_from_cache(query_ids, expire_window):
    '''
    description: 
    return {
        cache_identity_records: List[IdentityRecordSimplified],
        require_update_ids: List[str], # which exist in cache but expired (return old data first to speed up response)
        missing_query_ids: List[str],  # which not exist in cache, must query_from_db
    }
    '''
    try:
        require_update_ids = []
        missing_query_ids = []
        cache_identity_records = []
        redis_client = await RedisClient.get_instance()

        aliases_keys = []
        for query_id in query_ids:
            aliases_keys.append(f"aliases:{query_id}")
        aliases_keys = list(set(aliases_keys))

        aliases_values_tasks = [RedisClient.get_set(key) for key in aliases_keys]
        aliases_values = await asyncio.gather(*aliases_values_tasks)
        aliases_cache_item = dict(zip(aliases_keys, aliases_values))

        profile_map_aliases_key = {}
        for alias_cache_key_bytes, profile_cache_keys in aliases_cache_item.items():
            alias_cache_key = alias_cache_key_bytes.decode("utf-8") if isinstance(alias_cache_key_bytes, bytes) else alias_cache_key_bytes
            # logging.info("get {} {}".format(alias_cache_key, profile_cache_keys))
            if not profile_cache_keys:
                missing_query_ids.append(alias_cache_key.removeprefix("aliases:"))
            else:
                for profile_cache_key in profile_cache_keys:
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

async def set_lens_empty_profile_to_cache(query_id, empty_record, expire_window):
    # random_offset = 0
    random_offset = random.randint(0, 30 * 60)  # Adding up to 30 minutes of randomness
    final_expire_window = expire_window + random_offset

    profile_cache_key = f"profile:{query_id}"  # e.g. profile:lens,#notexist_profile_id which is not exist
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


async def batch_set_lens_profile_to_cache(exist_identity_records: typing.List[IdentityRecordSimplified], expire_window):
    aliases_map = {}
    for cache_identity_record in exist_identity_records:
        random_offset = random.randint(0, 30 * 60)  # Adding up to 30 minutes of randomness
        final_expire_window = expire_window + random_offset

        primary_id = cache_identity_record.id
        profile_cache_key = f"profile:{primary_id}"  # e.g. profile:lens,zella.lens
        profile_lock_key = f"{primary_id}.lock"

        aliases = cache_identity_record.aliases
        for alias in aliases:
            alias_cache_key = f"aliases:{alias}"
            if alias_cache_key not in aliases_map:
                aliases_map[alias_cache_key] = []
            aliases_map[alias_cache_key].append(profile_cache_key)

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

    if len(aliases_map) == 0:
        return

    unix_microseconds = get_unix_microseconds()
    aliases_lock_key = f"aliases:{unix_microseconds}.lock"
    aliases_unique_value = "{}:{}".format(aliases_lock_key, unix_microseconds)
    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(aliases_lock_key, aliases_unique_value, lock_timeout=30):
            # logging.debug(f"Lock acquired for key: {aliases_lock_key}")
            redis_client = await RedisClient.get_instance()
            for alias_cache_key, profile_key_values in aliases_map.items():
                # alias_cache_key: e.g. f"aliases:{platform,identity}"
                # Save the mapping from[alias_key] to [real profile_key]
                # lens address may hold multiple lens profile
                # logging.info("set({}) add to key {}".format(profile_key_values, alias_cache_key))
                await RedisClient.add_to_set(alias_cache_key, profile_key_values, ex=final_expire_window)
            # logging.debug(f"Cache updated aliases[{aliases_lock_key}] map to key[{profile_cache_key}]")
        else:
            logging.warning(f"Could not acquire lock for key: {aliases_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(aliases_lock_key, aliases_unique_value)
        # logging.debug(f"Lock released for key: {aliases_lock_key}")

async def set_lens_profile_to_cache(cache_identity_record: IdentityRecordSimplified, expire_window):
    # random_offset = 0
    random_offset = random.randint(0, 30 * 60)  # Adding up to 30 minutes of randomness
    final_expire_window = expire_window + random_offset

    primary_id = cache_identity_record.id
    profile_cache_key = f"profile:{primary_id}"  # e.g. profile:lens,zella.lens
    profile_lock_key = f"{primary_id}.lock"

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
                alias_cache_key = f"aliases:{alias}"
                # Save the mapping from[alias_key] to [real profile_key]
                # logging.info("{} => {}".format(alias_cache_key, profile_cache_key))
                await redis_client.set(alias_cache_key, profile_cache_key, ex=final_expire_window)
            # logging.debug(f"Cache updated aliases[{aliases_lock_key}] map to key[{profile_cache_key}]")
        else:
            logging.warning(f"Could not acquire lock for key: {aliases_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(aliases_lock_key, aliases_unique_value)
        # logging.debug(f"Lock released for key: {aliases_lock_key}")

async def batch_query_profile_by_profile_ids_db(query_ids) -> typing.List[IdentityRecordSimplified]:
    lens_profile_ids = []
    lens_handles = []
    lens_owners = []
    for _id in query_ids:
        identity = _id.split(",")[1]
        if identity.startswith('#'):
            lens_profile_ids.append(int(identity.removeprefix('#')))
        else:
            is_evm = is_ethereum_address(identity)
            if is_evm:
                lens_owners.append(identity)
            else:
                lens_handles.append(identity)

    lens_profile_ids = list(set(lens_profile_ids))
    lens_handles = list(set(lens_handles))
    lens_owners = list(set(lens_owners))

    # No need to select fields anymore, just query all fields
    profile_fields,\
    social_fields = get_lens_fields()

    profile_dict = {}
    social_dict = {}
    result_profile_ids = []

    async with get_session() as s:
        filters = []
        if lens_profile_ids:
            filters.append(LensV2Profile.profile_id.in_(lens_profile_ids))
        if lens_handles:
            filters.append(LensV2Profile.name.in_(lens_handles))
        if lens_owners:
            filters.append(LensV2Profile.address.in_(lens_owners))

        if filters:
            filters_obj = or_(*filters)
            profile_sql = select(LensV2Profile).options(
                load_only(*profile_fields))\
                .filter(filters_obj)
            profile_result = await s.execute(profile_sql)
            profile_records = profile_result.scalars().all()
            for row in profile_records:
                result_profile_ids.append(row.profile_id)
                profile_dict[row.profile_id] = row

        if result_profile_ids:
            social_sql = select(LensV2Social).options(
                load_only(*social_fields))\
                .filter(LensV2Social.profile_id.in_(result_profile_ids))
            social_result = await s.execute(social_sql)
            social_records = social_result.scalars().all()
            for row in social_records:
                social_dict[row.profile_id] = row

    result = []
    for profile_id in result_profile_ids:
        profile_record: LensV2Profile = profile_dict.get(profile_id, None)
        name = profile_record.name
        if name is None:
            continue
        
        aliases = []
        aliases.append("{},#{}".format(Platform.lens.value, profile_id))
        aliases.append("{},{}".format(Platform.lens.value, name))
        network = None
        resolved_addresses = []
        owner_addresses = []
        records = []
        address = profile_record.address
        if address is not None:
            network = Network.ethereum
            resolved_addresses.append(Address(address=address, network=network))
            owner_addresses.append(Address(address=address, network=network))
            records.append(Address(address=address, network=network))
            aliases.append("{},{}".format(Platform.lens.value, address))

        texts = profile_record.texts
        if texts:
            # Filter out empty strings and decode non-empty texts
            process_texts = {key: unquote(text, 'utf-8') for key, text in texts.items() if text != ""}
            texts = process_texts

        if not texts:
            texts = None

        cover_picture = profile_record.cover_picture
        if cover_picture is not None:
            if texts is not None:
                texts["header"] = cover_picture
            else:
                texts = {"header": cover_picture}

        social = None
        if profile_record is not None:
            profile = Profile(
                uid=profile_id,
                identity=name,
                platform=Platform.lens,
                network=network,
                address=address,
                display_name=profile_record.display_name,
                avatar=profile_record.avatar,
                description=profile_record.description,
                texts=texts,
                addresses=records,
                social=None,
            )
            if social_dict:
                social_info = social_dict.get(profile_id, None)
                if social_info:
                    social = SocialProfile(
                        uid=profile_id,
                        following=social_info.following,
                        follower=social_info.follower,
                        updated_at=social_info.update_time,
                    )
                    profile.social = social
            
            result.append(IdentityRecordSimplified(
                id=f"{Platform.lens.value},{name}",
                aliases=aliases,
                identity=name,
                platform=Platform.lens,
                network=network,
                primary_name=None,
                is_primary=profile_record.is_primary,
                expired_at=None,
                resolved_address=resolved_addresses,
                owner_address=owner_addresses,
                profile=profile
            ))
    return result

async def query_and_update_missing_query_ids(query_ids):
    # logging.debug("query_and_update_missing_query_ids input %s", query_ids)
    identity_records = await batch_query_profile_by_profile_ids_db(query_ids)
    # need cache where query_id is not in storage to avoid frequency access db

    exists_query_ids = []
    for record in identity_records:
        exists_query_ids.extend(record.aliases)

    if identity_records:
        asyncio.create_task(batch_set_lens_profile_to_cache(identity_records, expire_window=24*3600))

    empty_query_ids = list(set(query_ids) - set(exists_query_ids))
    for empty_query_id in empty_query_ids:
        asyncio.create_task(set_lens_empty_profile_to_cache(empty_query_id, {}, expire_window=24*3600))

    return identity_records

def filter_lens_query_ids(identities):
    final_query_ids = set()
    for identity in identities:
        if identity.startswith('#'):
            try:
                query_profile_id = int(copy.deepcopy(identity).removeprefix('#'))
                final_query_ids.add(f"{Platform.lens.value},{identity}")
            except:
                continue
        else:
            is_evm = is_ethereum_address(identity)
            if is_evm:
                final_query_ids.add(f"{Platform.lens.value},{identity}")
            else:
                if 4 < len(identity) < 256:
                    final_query_ids.add(f"{Platform.lens.value},{identity}")

    return list(final_query_ids)

async def query_lens_profile_by_ids_cache(info, identities, require_cache=False):
    if len(identities) > QUERY_MAX_LIMIT:
        return ExceedRangeInput(QUERY_MAX_LIMIT)

    filter_query_ids = filter_lens_query_ids(identities)
    if len(filter_query_ids) == 0:
        return []

    identity_records = []
    if require_cache is False:
        # query data from db and return immediately
        logging.info("lens filter_input_ids %s", filter_query_ids)
        identity_records = await batch_query_profile_by_profile_ids_db(filter_query_ids)
        return identity_records

    # require_cache is True:
    cache_identity_records, \
    require_update_ids, \
    missing_query_ids = await get_lens_profile_from_cache(filter_query_ids, expire_window=12*3600)

    logging.info("lens input filter_query_ids: {}".format(filter_query_ids))
    # logging.debug("lens missing_query_ids: {}".format(missing_query_ids))
    # logging.debug("lens require_update_ids: {}".format(require_update_ids))
    # logging.debug("lens cache_identity_records: {}".format(len(cache_identity_records)))

    final_identity_records = cache_identity_records.copy()
    if missing_query_ids:
        logging.info("lens missing data {}".format(missing_query_ids))
        missing_identity_records = await query_and_update_missing_query_ids(missing_query_ids)
        final_identity_records.extend(missing_identity_records)

    if require_update_ids:
        logging.info("lens has olddata and return immediately {}".format(require_update_ids))
        # Update background
        asyncio.create_task(query_and_update_missing_query_ids(require_update_ids))

    return final_identity_records
