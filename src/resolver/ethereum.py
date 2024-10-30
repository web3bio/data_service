#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 18:41:34
LastEditors: Zella Zhong
LastEditTime: 2024-10-30 15:10:26
FilePath: /data_service/src/resolver/ethereum.py
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
from model import EnsnameModel
from cache.redis import RedisClient

from utils import convert_camel_case, check_evm_address
from utils.address import is_ethereum_address, is_base58_solana_address
from utils.timeutils import get_unix_microseconds, parse_time_string, get_current_time_string

from scalar.platform import Platform
from scalar.network import Network, Address, CoinTypeMap
from scalar.identity_graph import IdentityRecordSimplified
from scalar.identity_record import IdentityRecord
from scalar.profile import Profile, SocialProfile
from scalar.error import EmptyInput, EvmAddressInvalid, ExceedRangeInput
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

def get_profile_selected_fields(db_baseclass_name, info):
    attr_names = [c_attr.key for c_attr in inspect(db_baseclass_name).mapper.column_attrs]
    # Extract selected fields from the `info` object
    base_selected_fields = ["name", "resolved_address", "reverse_address", "is_primary"]
    filter_selected_fields = []
    filter_selected_fields.extend(base_selected_fields)
    info_selected_fields = info.selected_fields[0].selections

    for field in info_selected_fields:
        field_name = convert_camel_case(field.name)
        match field_name:
            case "id":
                continue
            case "identity":
                continue
            case "platform":
                continue
            case "network":
                continue
            case "primary_name":
                filter_selected_fields.append("name")
            case "is_primary":
                filter_selected_fields.append("is_primary")
            case "resolved_address":
                continue
            case "owner_address":
                continue
            case "expired_at":
                filter_selected_fields.append("expire_time")
            case "profile":
                profile_selected_fields = get_selected_fields("profile", info_selected_fields)
                if profile_selected_fields:
                    for profile_field in profile_selected_fields:
                        profile_field_name = convert_camel_case(profile_field.name)
                        match profile_field_name:
                            case "identity":
                                continue
                            case "platform":
                                continue
                            case "address":
                                continue
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
                                continue
                            case "platform":
                                continue
                            case "network":
                                continue
                            case "primary_name":
                                filter_selected_fields.append("name")
                            case "is_primary":
                                filter_selected_fields.append("is_primary")
                            case "resolved_address":
                                continue
                            case "owner_address":
                                continue
                            case "expired_at":
                                filter_selected_fields.append("expire_time")
                            case "profile":
                                profile_selected_fields = get_selected_fields("profile", info_selected_fields)
                                if profile_selected_fields:
                                    for profile_field in profile_selected_fields:
                                        profile_field_name = convert_camel_case(profile_field.name)
                                        match profile_field_name:
                                            case "identity":
                                                continue
                                            case "platform":
                                                continue
                                            case "address":
                                                continue
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

    # selected_fields = [convert_camel_case(field.name) for field in info_selected_fields]
    # logging.info("selected_fields: %s", selected_fields)

    # profile_selected_fields = get_selected_fields("profile", info_selected_fields)
    # if profile_selected_fields:
    #     profile_field_names = [convert_camel_case(field.name) for field in profile_selected_fields]
    #     logging.info("Profile selected fields: %s", profile_field_names)

    match_selected_fields = list(set(attr_names) & set(filter_selected_fields))
    # logging.info("Match selected fields: %s", match_selected_fields)
    match_selected_fields = [getattr(db_baseclass_name, f) for f in match_selected_fields]
    return match_selected_fields

async def query_profile_by_single_address(info, address):
    checked_address = None
    if not check_evm_address(address):
        return EvmAddressInvalid(address)
    checked_address = address.lower()

    selected_fields = get_profile_selected_fields(EnsnameModel, info)
    async with get_session() as s:
        sql = select(EnsnameModel).options(load_only(*selected_fields)) \
            .filter(EnsnameModel.reverse_address == checked_address)
        result = await s.execute(sql)
        db_result = result.scalars().one_or_none()

    if db_result is None:
        return IdentityRecord(
            id=f"{Platform.ethereum.value},{checked_address}",
            identity=checked_address,
            platform=Platform.ethereum,
            network=Network.ethereum,
            primary_name=None,
            is_primary=False,
            profile=None
        )

    profile_record = {key: value for key, value in db_result.__dict__.items()}
    name = profile_record.get('name', None)
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

    network = None
    address = profile_record.get('resolved_address', None)
    if address is not None:
        network = Network.ethereum

    profile = Profile(
        uid=None,
        identity=name,
        platform=Platform.ens,
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
    address_primary_id = f"{Platform.ethereum.value},{checked_address}"
    aliases = [address_primary_id]
    identity_record = IdentityRecord(
        id=address_primary_id,
        aliases=aliases,
        identity=checked_address,
        platform=Platform.ethereum,
        network=Network.ethereum,
        primary_name=profile_record.get('name', None),
        is_primary=profile_record.get('is_primary', False),
        expired_at=profile_record.get('expire_time', None),
        profile=profile
    )
    return identity_record

async def query_profile_by_addresses(info, addresses):
    # if len(addresses) == 0:
    #     return EmptyInput()
    if len(addresses) > QUERY_MAX_LIMIT:
        return ExceedRangeInput(QUERY_MAX_LIMIT)
    # logging.debug("query_profile_by_addresses %s", addresses)
    checked_addresses = []
    for addr in addresses:
        if not check_evm_address(addr):
            return EvmAddressInvalid(addr)
        checked_addresses.append(addr.lower())


    selected_fields = get_profile_selected_fields(EnsnameModel, info)
    db_dict = {}
    async with get_session() as s:
        sql = select(EnsnameModel).options(load_only(*selected_fields)) \
            .filter(EnsnameModel.reverse_address.in_(checked_addresses)
                    )
        result = await s.execute(sql)
        db_records = result.scalars().all()
        for row in db_records:
            # db_dict[row.reverse_address] = {key: value for key, value in row.__dict__.items() if not key.startswith('_')}
            db_dict[row.reverse_address] = {key: value for key, value in row.__dict__.items()}
    result = []
    for addr in checked_addresses:
        profile_record = db_dict.get(addr, None)
        if profile_record is None:
            result.append(IdentityRecordSimplified(
                id=f"{Platform.ethereum.value},{addr}",
                identity=addr,
                platform=Platform.ethereum,
                network=Network.ethereum,
                primary_name=None,
                is_primary=False,
                profile=None
            ))
        else:
            # Ensure 'texts' exists dynamically using hasattr()
            name = profile_record.get('name', None)
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

            network = None
            address = profile_record.get('resolved_address', None)
            if address is not None:
                network = Network.ethereum
            profile = Profile(
                uid=None,
                identity=name,
                platform=Platform.ens,
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
                id=f"{Platform.ethereum.value},{addr}",
                identity=addr,
                platform=Platform.ethereum,
                network=Network.ethereum,
                primary_name=profile_record.get('name', None),
                is_primary=profile_record.get('is_primary', False),
                expired_at=profile_record.get('expire_time', None),
                profile=profile
            ))

    return result

def get_ethereum_fields():
    '''
    description: retrieve all fields
    return {*}
    '''    
    # Get all fields for each model using reflection
    profile_fields = [getattr(EnsnameModel, c.key) for c in inspect(EnsnameModel).mapper.column_attrs]
    return profile_fields

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

async def get_ethereum_profile_from_cache(query_ids, expire_window):
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

        profile_cache_keys = []
        for query_id in query_ids:
            profile_cache_keys.append(f"profile:{query_id}")

        profile_json_values = await redis_client.mget(*profile_cache_keys)
        profile_cache_json_values = dict(zip(profile_cache_keys, profile_json_values))
        for profile_cache_key_bytes, profile_json_value_bytes in profile_cache_json_values.items():
            profile_cache_key = profile_cache_key_bytes.decode("utf-8") if isinstance(profile_cache_key_bytes, bytes) else profile_cache_key_bytes
            profile_json_value = profile_json_value_bytes.decode("utf-8") if profile_json_value_bytes is not None else None

            if profile_json_value is None:
                missing_query_ids.append(profile_cache_key.removeprefix("profile:"))
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

async def set_ethereum_profile_to_cache(cache_identity_record: IdentityRecordSimplified, expire_window):
    random_offset = random.randint(0, 30 * 60)  # Adding up to 30 minutes of randomness
    # random_offset = 0
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

async def batch_query_profile_by_address_db(query_ids) -> typing.List[IdentityRecordSimplified]:
    checked_addresses = []
    for _id in query_ids:
        identity = _id.split(",")[1]
        is_evm = is_ethereum_address(identity)
        if is_evm:
            checked_addresses.append(identity)

    # logging.debug("checked_addresses = %s", checked_addresses)

    # No need to select fields anymore, just query all fields
    profile_fields = get_ethereum_fields()
    profile_dict = {}
    async with get_session() as s:
        sql = select(EnsnameModel).options(load_only(*profile_fields)) \
            .filter(EnsnameModel.reverse_address.in_(checked_addresses))
        result = await s.execute(sql)
        db_records = result.scalars().all()
        for row in db_records:
            profile_dict[row.reverse_address] = row

    result = []
    for addr in checked_addresses:
        profile_record: EnsnameModel = profile_dict.get(addr, None)
        if profile_record is None:
            address_primary_id = f"{Platform.ethereum.value},{addr}"
            aliases = [address_primary_id]
            result.append(IdentityRecordSimplified(
                id=address_primary_id,
                aliases=aliases,
                identity=addr,
                platform=Platform.ethereum,
                network=Network.ethereum,
                primary_name=None,
                is_primary=False,
                profile=None
            ))
        else:
            # Ensure 'texts' exists dynamically using hasattr()
            name = profile_record.name
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

            network = None
            address = profile_record.resolved_address
            if address is not None:
                network = Network.ethereum
            profile = Profile(
                uid=None,
                identity=name,
                platform=Platform.ens,
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

            address_primary_id = f"{Platform.ethereum.value},{addr}"
            aliases = [address_primary_id]
            result.append(IdentityRecordSimplified(
                id=address_primary_id,
                aliases=aliases,
                identity=addr,
                platform=Platform.ethereum,
                network=Network.ethereum,
                primary_name=profile_record.name,
                is_primary=profile_record.is_primary,
                expired_at=profile_record.expire_time,
                profile=profile
            ))
    return result

async def query_and_update_missing_query_ids(query_ids):
    # logging.debug("query_and_update_missing_query_ids input %s", query_ids)
    identity_records = await batch_query_profile_by_address_db(query_ids)
    # need cache where query_id is not in storage to avoid frequency access db

    # exists_query_ids = []
    for record in identity_records:
        # exists_query_ids.extend(record.aliases)
        asyncio.create_task(set_ethereum_profile_to_cache(record, expire_window=24*3600))

    return identity_records

def filter_ethereum_query_ids(identities):
    final_query_ids = set()
    for identity in identities:
        is_evm = is_ethereum_address(identity)
        if is_evm:
            final_query_ids.add(f"{Platform.ethereum.value},{identity}")

    return list(final_query_ids)

async def query_ethereum_profile_by_ids_cache(info, identities, require_cache=False):
    if len(identities) > QUERY_MAX_LIMIT:
        return ExceedRangeInput(QUERY_MAX_LIMIT)

    filter_query_ids = filter_ethereum_query_ids(identities)
    if len(filter_query_ids) == 0:
        return []

    identity_records = []
    if require_cache is False:
        # query data from db and return immediately
        logging.info("ethereum input %s", filter_query_ids)
        identity_records = await batch_query_profile_by_address_db(filter_query_ids)
        return identity_records

    # require_cache is True:
    cache_identity_records, \
    require_update_ids, \
    missing_query_ids = await get_ethereum_profile_from_cache(filter_query_ids, expire_window=12*3600)

    logging.info("ethereum input filter_query_ids: {}".format(filter_query_ids))
    # logging.debug("ethereum missing_query_ids: {}".format(missing_query_ids))
    # logging.debug("ethereum require_update_ids: {}".format(require_update_ids))
    # logging.debug("ethereum cache_identity_records: {}".format(len(cache_identity_records)))

    final_identity_records = cache_identity_records.copy()
    if missing_query_ids:
        logging.info("ethereum missing data {}".format(missing_query_ids))
        missing_identity_records = await query_and_update_missing_query_ids(missing_query_ids)
        final_identity_records.extend(missing_identity_records)

    if require_update_ids:
        logging.info("ethereum has olddata and return immediately {}".format(require_update_ids))
        # Update background
        asyncio.create_task(query_and_update_missing_query_ids(require_update_ids))

    return final_identity_records
