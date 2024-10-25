#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 21:38:55
LastEditors: Zella Zhong
LastEditTime: 2024-10-25 22:20:09
FilePath: /data_service/src/resolver/farcaster.py
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
from model.farcaster import FarcasterProfile, FarcasterVerified, FarcasterSocial, FarcasterFnames
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


def get_farcaster_selected_fields(info):
    info_selected_fields = info.selected_fields[0].selections

    profile_fields = ["fid", "fname", "network", "address"]
    verified_fields = []
    social_fields = []
    for field in info_selected_fields:
        field_name = convert_camel_case(field.name)
        match field_name:
            case "id":
                continue
            case "identity":
                profile_fields.append("fid")
                profile_fields.append("fname")
            case "platform":
                continue
            case "network":
                profile_fields.append("network")
            case "primary_name":
                profile_fields.append("fname")
            case "is_primary":
                continue
            case "resolved_address":
                continue
            case "owner_address":
                verified_fields.append("fid")
                verified_fields.append("network")
                verified_fields.append("address")
            case "expired_at":
                continue
            case "profile":
                profile_selected_fields = get_selected_fields("profile", info_selected_fields)
                if profile_selected_fields:
                    for profile_field in profile_selected_fields:
                        profile_field_name = convert_camel_case(profile_field.name)
                        match profile_field_name:
                            case "identity":
                                profile_fields.append("fid")
                                profile_fields.append("fname")
                            case "platform":
                                continue
                            case "address":
                                profile_fields.append("network")
                                profile_fields.append("address")
                            case "display_name":
                                profile_fields.append("display_name")
                            case "avatar":
                                profile_fields.append("avatar")
                            case "cover_picture":
                                profile_fields.append("cover_picture")
                            case "description":
                                profile_fields.append("description")
                            case "contenthash":
                                continue
                            case "texts":
                                continue
                            case "addresses":
                                verified_fields.append("fid")
                                verified_fields.append("network")
                                verified_fields.append("address")
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
                                            case "update_at":
                                                social_fields.append("update_time")
                            case _:
                                continue
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
                                profile_fields.append("fid")
                                profile_fields.append("fname")
                            case "platform":
                                continue
                            case "network":
                                profile_fields.append("network")
                            case "primary_name":
                                profile_fields.append("fname")
                            case "is_primary":
                                continue
                            case "resolved_address":
                                continue
                            case "owner_address":
                                verified_fields.append("fid")
                                verified_fields.append("network")
                                verified_fields.append("address")
                            case "expired_at":
                                continue
                            case "profile":
                                profile_selected_fields = get_selected_fields("profile", info_selected_fields)
                                if profile_selected_fields:
                                    for profile_field in profile_selected_fields:
                                        profile_field_name = convert_camel_case(profile_field.name)
                                        match profile_field_name:
                                            case "identity":
                                                profile_fields.append("fid")
                                                profile_fields.append("fname")
                                            case "platform":
                                                continue
                                            case "address":
                                                profile_fields.append("network")
                                                profile_fields.append("address")
                                            case "display_name":
                                                profile_fields.append("display_name")
                                            case "avatar":
                                                profile_fields.append("avatar")
                                            case "cover_picture":
                                                profile_fields.append("cover_picture")
                                            case "description":
                                                profile_fields.append("description")
                                            case "contenthash":
                                                continue
                                            case "texts":
                                                continue
                                            case "addresses":
                                                verified_fields.append("fid")
                                                verified_fields.append("network")
                                                verified_fields.append("address")
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
                                                            case "update_at":
                                                                social_fields.append("update_time")
            # If an exact match is not confirmed, this last case will be used if provided
            case _:
                continue

    profile_fields = list(
        set([c_attr.key for c_attr in inspect(FarcasterProfile).mapper.column_attrs]) \
        & set(profile_fields))
    verified_fields = list(
        set([c_attr.key for c_attr in inspect(FarcasterVerified).mapper.column_attrs]) \
        & set(verified_fields))
    social_fields = list(
        set([c_attr.key for c_attr in inspect(FarcasterSocial).mapper.column_attrs]) \
        & set(social_fields))
    # logging.info("Match profile_fields: %s", profile_fields)
    # logging.info("Match verified_fields: %s", verified_fields)
    # logging.info("Match social_fields: %s", social_fields)

    profile_fields = [getattr(FarcasterProfile, f) for f in profile_fields]
    verified_fields = [getattr(FarcasterVerified, f) for f in verified_fields]
    social_fields = [getattr(FarcasterSocial, f) for f in social_fields]
    return profile_fields, verified_fields, social_fields

async def query_profile_by_single_fname(info, fname):
    profile_fields,\
    verified_fields,\
    social_fields = get_farcaster_selected_fields(info)

    profile_record = None
    fid = None
    owner_addresses = []
    records = []
    social_record = None
    async with get_session() as s:
        if len(profile_fields) > 0:
            profile_sql = select(FarcasterProfile).options(
                load_only(*profile_fields))\
                .filter(FarcasterProfile.fname == fname)
            profile_result = await s.execute(profile_sql)
            one_profile_record = profile_result.scalars().one_or_none()
            if one_profile_record is not None:
                fid = one_profile_record.fid
                profile_record = {key: value for key, value in one_profile_record.__dict__.items()}

        if len(verified_fields) > 0:
            if fid is not None:
                verified_sql = select(FarcasterVerified).options(
                    load_only(*verified_fields))\
                    .filter(FarcasterVerified.fid == fid)
                verified_result = await s.execute(verified_sql)
                verified_records = verified_result.scalars().all()
                for row in verified_records:
                    owner_addresses.append(Address(address=row.address, network=row.network))
                    records.append(Address(address=row.address, network=row.network))

        if len(social_fields) > 0:
            if fid is not None:
                social_sql = select(FarcasterSocial).options(
                    load_only(*social_fields))\
                    .filter(FarcasterSocial.fid == fid)
                social_result = await s.execute(social_sql)
                one_social_record = social_result.scalars().one_or_none()
                if one_social_record is not None:
                    social_record = {key: value for key, value in one_social_record.__dict__.items()}

    if profile_record is None:
        return None

    fname = profile_record.get('fname', None)
    network = profile_record.get('network', None)
    address = profile_record.get('address', None)
    if fname is None:
        return None

    profile = Profile(
        uid=fid,
        identity=fname,
        platform=Platform.farcaster,
        network=network,
        address=address,
        display_name=profile_record.get('display_name', None),
        avatar=profile_record.get('avatar', None),
        description=profile_record.get('description', None),
        addresses=records,
        social=None,
    )

    if social_record:
        social = SocialProfile(
            uid=fid,
            following=social_record.get('following', 0),
            follower=social_record.get('follower', 0),
            update_at=social_record.get('update_time', None),
        )
        profile.social = social

    identity_record = IdentityRecord(
        id=f"{Platform.farcaster.value},{fname}",
        identity=fname,
        platform=Platform.farcaster,
        network=network,
        primary_name=None,
        is_primary=False,
        expired_at=None,
        resolved_address=[],
        owner_address=owner_addresses,
        profile=profile
    )
    return identity_record

async def query_profile_by_fnames(info, fnames):
    # if len(fnames) == 0:
    #     return EmptyInput()

    if len(fnames) > QUERY_MAX_LIMIT:
        return ExceedRangeInput(QUERY_MAX_LIMIT)

    logging.debug("query_profile_by_fnames %s", fnames)
    profile_fields,\
    verified_fields,\
    social_fields = get_farcaster_selected_fields(info)

    profile_dict = {}
    fids = []
    verified_dict = {}
    social_dict = {}
    async with get_session() as s:
        if len(profile_fields) > 0:
            profile_sql = select(FarcasterProfile).options(
                load_only(*profile_fields))\
                .filter(FarcasterProfile.fname.in_(fnames))
            profile_result = await s.execute(profile_sql)
            profile_records = profile_result.scalars().all()
            for row in profile_records:
                fids.append(row.fid)
                profile_dict[row.fid] = {key: value for key, value in row.__dict__.items()}

        if len(verified_fields) > 0:
            verified_sql = select(FarcasterVerified).options(
                load_only(*verified_fields))\
                .filter(FarcasterVerified.fid.in_(fids))
            verified_result = await s.execute(verified_sql)
            verified_records = verified_result.scalars().all()
            for row in verified_records:
                if row.fid not in verified_dict:
                    verified_dict[row.fid] = []
                verified_dict[row.fid].append(row)

        if len(social_fields) > 0:
            social_sql = select(FarcasterSocial).options(
                load_only(*social_fields))\
                .filter(FarcasterSocial.fid.in_(fids))
            social_result = await s.execute(social_sql)
            social_records = social_result.scalars().all()
            for row in social_records:
                social_dict[row.fid] = {key: value for key, value in row.__dict__.items()}

    result = []
    for fid in fids:
        profile_record = profile_dict.get(fid, None)
        fname = profile_record.get('fname', None)
        network = profile_record.get('network', None)
        address = profile_record.get('address', None)
        if fname is None:
            continue
        owner_addresses = []
        records = []
        social = None
        if profile_record is not None:
            profile = Profile(
                uid=fid,
                identity=fname,
                platform=Platform.farcaster,
                network=network,
                address=address,
                display_name=profile_record.get('display_name', None),
                avatar=profile_record.get('avatar', None),
                description=profile_record.get('description', None),
                social=None,
            )
            if verified_dict:
                verified_list = verified_dict.get(fid, [])
                for verified in verified_list:
                    owner_addresses.append(
                        Address(
                            address=verified.address,
                            network=verified.network,
                        )
                    )
                    records.append(
                        Address(
                            address=verified.address,
                            network=verified.network,
                        )
                    )
                profile.addresses = records

            if social_dict:
                social_info = social_dict.get(fid, None)
                if social_info:
                    social = SocialProfile(
                        uid=fid,
                        following=social_info.get('following', 0),
                        follower=social_info.get('follower', 0),
                        update_at=social_info.get('update_time', None),
                    )
                    profile.social = social

            result.append(IdentityRecordSimplified(
                id=f"{Platform.farcaster.value},{fname}",
                identity=fname,
                platform=Platform.farcaster,
                network=network,
                primary_name=None,
                is_primary=False,
                expired_at=None,
                resolved_address=[],
                owner_address=owner_addresses,
                profile=profile
            ))

    return result


def get_farcaster_fields():
    '''
    description: retrieve all fields
    return {*}
    '''    
    # Get all fields for each model using reflection
    profile_fields = [getattr(FarcasterProfile, c.key) for c in inspect(FarcasterProfile).mapper.column_attrs]
    verified_fields = [getattr(FarcasterVerified, c.key) for c in inspect(FarcasterVerified).mapper.column_attrs]
    social_fields = [getattr(FarcasterSocial, c.key) for c in inspect(FarcasterSocial).mapper.column_attrs]

    return profile_fields, verified_fields, social_fields

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
                    update_at=social_updated_at,
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

async def get_fids_by_input(query_ids):
    # logging.debug("get_fids_by_input query_ids: %s" % query_ids)
    final_fids = set()
    fnames = []
    verified_addresses = []
    for _id in query_ids:
        item = _id.split(",")
        if len(item) < 2:
            continue
        if item[0] != Platform.farcaster.value:
            continue

        query_id = item[1]
        if query_id.startswith('#'):
            try:
                query_fid = query_id.removeprefix('#')
                final_fids.add(int(query_fid))
            except:
                continue
        else:
            is_evm = is_ethereum_address(query_id)
            is_solana = is_base58_solana_address(query_id)
            if is_evm or is_solana:
                verified_addresses.append(query_id)
            else:
                fnames.append(query_id)

    async with get_session() as s:
        if fnames:
            fnames_fields = [getattr(FarcasterFnames, f) for f in ["fid", "fname"]]
            fnames_sql = (
                select(FarcasterFnames)
                .options(load_only(*fnames_fields))
                .filter(
                    and_(
                        FarcasterFnames.fname.in_(fnames),
                        FarcasterFnames.deleted_at.is_(None)  # Filter for non-deleted records
                    )
                )
            )
            fnames_result = await s.execute(fnames_sql)
            fnames_records = fnames_result.scalars().all()

            for row in fnames_records:
                final_fids.add(row.fid)

        if verified_addresses:
            address_fields = [getattr(FarcasterVerified, f) for f in ["fid", "address"]]
            address_sql = (
                select(FarcasterVerified)
                .options(load_only(*address_fields))
                .filter(
                    and_(
                        FarcasterVerified.address.in_(verified_addresses),
                        FarcasterVerified.delete_time.is_(None)  # Filter for non-deleted records
                    )
                )
            )
            address_result = await s.execute(address_sql)
            address_records = address_result.scalars().all()

            for row in address_records:
                final_fids.add(row.fid)

    return list(final_fids)


async def get_farcaster_profile_from_cache(query_ids, expire_window):
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
        aliases_values = await redis_client.mget(*aliases_keys)
        aliases_cache_item = dict(zip(aliases_keys, aliases_values))

        profile_map_aliases_key = {}
        for alias_cache_key_bytes, profile_cache_key_bytes in aliases_cache_item.items():
            alias_cache_key = alias_cache_key_bytes.decode("utf-8") if isinstance(alias_cache_key_bytes, bytes) else alias_cache_key_bytes
            profile_cache_key = profile_cache_key_bytes.decode("utf-8") if profile_cache_key_bytes is not None else None

            logging.debug(f"{alias_cache_key}: {profile_cache_key}")
            if profile_cache_key is None:
                missing_query_ids.append(alias_cache_key.removeprefix("aliases:"))
            else:
                if profile_cache_key not in profile_map_aliases_key:
                    profile_map_aliases_key[profile_cache_key] = []
                profile_map_aliases_key[profile_cache_key].append(alias_cache_key.removeprefix("aliases:"))

        profile_cache_keys = list(profile_map_aliases_key.keys())
        if profile_cache_keys:
            profile_json_values = await redis_client.mget(*profile_cache_keys)
            profile_cache_json_values = dict(zip(profile_cache_keys, profile_json_values))
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
                                logging.debug(f"Cache key {profile_cache_key} is empty. Returning old data, but marking for update.")
                                require_update_ids.append(profile_cache_key.removeprefix("profile:"))
                            else:
                                # Old data is returned, but it needs to be updated
                                logging.debug(f"Cache key {profile_cache_key} is expired. Returning old data, but marking for update.")
                                require_update_ids.append(profile_cache_key.removeprefix("profile:"))
                                cache_identity_records.append(
                                    convert_cache_to_identity_record(profile_value_dict)
                                )
                        else:
                            if len(profile_value_dict) == 1:
                                # only have one field(updated_at) is also not exist
                                logging.debug(f"Cache key {profile_cache_key} is empty but has been caching.")
                            else:
                                logging.debug(f"Cache key {profile_cache_key} has been caching.")
                                cache_identity_records.append(convert_cache_to_identity_record(profile_value_dict))

        return cache_identity_records, require_update_ids, missing_query_ids
    except Exception as ex:
        logging.exception(ex)
        # if cache logic is failed, just return query_from_db immediately
        return [], [], query_ids

async def set_farcaster_empty_profile_to_cache(query_id, empty_record, expire_window):
    random_offset = random.randint(0, 30 * 60)  # Adding up to 30 minutes of randomness
    # random_offset = 0
    final_expire_window = expire_window + random_offset

    profile_cache_key = f"profile:{query_id}"  # e.g. profile:farcaster,#1111111 which is not exist
    profile_lock_key = f"{query_id}.lock"

    profile_unique_value = "{}:{}".format(profile_lock_key, get_unix_microseconds())
    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(profile_lock_key, profile_unique_value, lock_timeout=30):
            logging.debug(f"Lock acquired for key: {profile_lock_key}")
            # Set the current time as 'updated_at' in "yyyy-mm-dd HH:MM:SS" format
            empty_record["updated_at"] = get_current_time_string()
            profile_value_json = json.dumps(empty_record)

            # Set the cache in Redis with the specified expiration time (in seconds)
            redis_client = await RedisClient.get_instance()
            await redis_client.set(profile_cache_key, profile_value_json, ex=final_expire_window)
            logging.debug(f"Cache updated for key: {profile_cache_key}")
        else:
            logging.warning(f"Could not acquire lock for key: {profile_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(profile_lock_key, profile_unique_value)
        logging.debug(f"Lock released for key: {profile_lock_key}")
    

    aliases_lock_key = f"aliases:{query_id}.lock"
    aliases_unique_value = "{}:{}".format(aliases_lock_key, get_unix_microseconds())
    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(aliases_lock_key, aliases_unique_value, lock_timeout=30):
            logging.debug(f"Lock acquired for key: {aliases_lock_key}")
            redis_client = await RedisClient.get_instance()
            # Save the empty query_id to [profile_key], and profile_key only have updated_at
            alias_cache_key = f"aliases:{query_id}"
            await redis_client.set(alias_cache_key, profile_cache_key, ex=final_expire_window)
            logging.debug(f"Cache updated aliases[{aliases_lock_key}] map to key[{profile_cache_key}]")
        else:
            logging.warning(f"Could not acquire lock for key: {aliases_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(aliases_lock_key, aliases_unique_value)
        logging.debug(f"Lock released for key: {aliases_lock_key}")


async def set_farcaster_profile_to_cache(cache_identity_record: IdentityRecordSimplified, expire_window):
    random_offset = random.randint(0, 30 * 60)  # Adding up to 30 minutes of randomness
    # random_offset = 0
    final_expire_window = expire_window + random_offset

    primary_id = cache_identity_record.id
    profile_cache_key = f"profile:{primary_id}"  # e.g. profile:farcaster,zella
    profile_lock_key = f"{primary_id}.lock"

    profile_unique_value = "{}:{}".format(profile_lock_key, get_unix_microseconds())
    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(profile_lock_key, profile_unique_value, lock_timeout=30):
            logging.debug(f"Lock acquired for key: {profile_lock_key}")
            # Set the current time as 'updated_at' in "yyyy-mm-dd HH:MM:SS" format
            cache_identity_record.updated_at = datetime.now()
            profile_value_json = strawberry_type_to_jsonstr(cache_identity_record)

            # Set the cache in Redis with the specified expiration time (in seconds)
            redis_client = await RedisClient.get_instance()
            await redis_client.set(profile_cache_key, profile_value_json, ex=final_expire_window)
            logging.debug(f"Cache updated for key: {profile_cache_key}")
        else:
            logging.warning(f"Could not acquire lock for key: {profile_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(profile_lock_key, profile_unique_value)
        logging.debug(f"Lock released for key: {profile_lock_key}")

    if len(cache_identity_record.aliases) == 0:
        return

    aliases_lock_key = f"aliases:{primary_id}.lock"
    aliases_unique_value = "{}:{}".format(aliases_lock_key, get_unix_microseconds())
    try:
        # Try acquiring the lock (with a timeout of 30 seconds)
        if await RedisClient.acquire_lock(aliases_lock_key, aliases_unique_value, lock_timeout=30):
            logging.debug(f"Lock acquired for key: {aliases_lock_key}")
            redis_client = await RedisClient.get_instance()
            for alias in cache_identity_record.aliases:
                alias_cache_key = f"aliases:{alias}"
                # Save the mapping from[alias_key] to [real profile_key]
                await redis_client.set(alias_cache_key, profile_cache_key, ex=final_expire_window)
            logging.debug(f"Cache updated aliases[{aliases_lock_key}] map to key[{profile_cache_key}]")
        else:
            logging.warning(f"Could not acquire lock for key: {aliases_lock_key}")

    finally:
        # Always release the lock after the critical section is done
        await RedisClient.release_lock(aliases_lock_key, aliases_unique_value)
        logging.debug(f"Lock released for key: {aliases_lock_key}")

async def batch_query_profile_by_fids_db(fids) -> typing.List[IdentityRecordSimplified]:
    # No need to select fields anymore, just query all fields
    profile_fields,\
    verified_fields,\
    social_fields = get_farcaster_fields()

    profile_dict = {}
    verified_dict = {}
    social_dict = {}
    result_fids = []

    async with get_session() as s:
        if fids:
            profile_sql = select(FarcasterProfile).options(
                load_only(*profile_fields))\
                .filter(FarcasterProfile.fid.in_(fids))
            profile_result = await s.execute(profile_sql)
            profile_records = profile_result.scalars().all()
            for row in profile_records:
                result_fids.append(row.fid)
                profile_dict[row.fid] = row

            verified_sql = select(FarcasterVerified).options(
                load_only(*verified_fields))\
                .filter(FarcasterVerified.fid.in_(fids))
            verified_result = await s.execute(verified_sql)
            verified_records = verified_result.scalars().all()
            for row in verified_records:
                if row.fid not in verified_dict:
                    verified_dict[row.fid] = []
                verified_dict[row.fid].append(row)

            social_sql = select(FarcasterSocial).options(
                load_only(*social_fields))\
                .filter(FarcasterSocial.fid.in_(fids))
            social_result = await s.execute(social_sql)
            social_records = social_result.scalars().all()
            for row in social_records:
                social_dict[row.fid] = row

    result = []
    for fid in result_fids:
        profile_record: FarcasterProfile = profile_dict.get(fid, None)
        fname = profile_record.fname
        network = profile_record.network
        address = profile_record.address
        if fname is None:
            continue
        owner_addresses = []
        records = []
        social = None
        aliases = []
        if profile_record is not None:
            # add # for uid
            aliases.append("{},#{}".format(Platform.farcaster.value, fid))
            if profile_record.alias:
                for alias_fname in profile_record.alias:
                    aliases.append("{},{}".format(Platform.farcaster.value, alias_fname))
            profile = Profile(
                uid=fid,
                identity=fname,
                platform=Platform.farcaster,
                network=network,
                address=address,
                display_name=profile_record.display_name,
                avatar=profile_record.avatar,
                description=profile_record.description,
                social=None,
            )
            if verified_dict:
                verified_list = verified_dict.get(fid, [])
                for verified in verified_list:
                    owner_addresses.append(
                        Address(
                            address=verified.address,
                            network=verified.network,
                        )
                    )
                    records.append(
                        Address(
                            address=verified.address,
                            network=verified.network,
                        )
                    )
                    aliases.append("{},{}".format(Platform.farcaster.value, verified.address))
                profile.addresses = records

            if social_dict:
                social_info: FarcasterSocial = social_dict.get(fid, None)
                if social_info:
                    social = SocialProfile(
                        uid=fid,
                        following=social_info.following,
                        follower=social_info.follower,
                        update_at=social_info.update_time,
                    )
                    profile.social = social

            result.append(IdentityRecordSimplified(
                id=f"{Platform.farcaster.value},{fname}",
                aliases=aliases,
                identity=fname,
                platform=Platform.farcaster,
                network=network,
                primary_name=None,
                is_primary=False,
                expired_at=None,
                resolved_address=[],
                owner_address=owner_addresses,
                profile=profile
            ))

    return result

async def query_and_update_missing_query_ids(query_ids):
    fids = await get_fids_by_input(query_ids)
    logging.debug("query_and_update_missing_query_ids input %s turn to fids: %s", query_ids, fids)
    identity_records = await batch_query_profile_by_fids_db(fids)
    # need cache where query_id is not in storage to avoid frequency access db

    exists_query_ids = []
    for record in identity_records:
        exists_query_ids.extend(record.aliases)
        asyncio.create_task(set_farcaster_profile_to_cache(record, expire_window=24*3600))

    empty_query_ids = list(set(query_ids) - set(exists_query_ids))
    for empty_query_id in empty_query_ids:
        asyncio.create_task(set_farcaster_empty_profile_to_cache(empty_query_id, {}, expire_window=60))

    return identity_records

async def batch_query_profile_by_ids_cache(info, query_ids, require_cache=False):
    if len(query_ids) > QUERY_MAX_LIMIT:
        return ExceedRangeInput(QUERY_MAX_LIMIT)

    identity_records = []
    if require_cache is False:
        # query data from db and return immediately
        fids = await get_fids_by_input(query_ids)
        logging.debug("batch_query_profile_by_ids_cache input %s turn to fids: %s", query_ids, fids)
        identity_records = await batch_query_profile_by_fids_db(fids)
        return identity_records

    # require_cache is True:
    cache_identity_records, \
    require_update_ids, \
    missing_query_ids = await get_farcaster_profile_from_cache(query_ids, expire_window=12*3600)

    logging.debug("batch_query_profile_by_ids_cache input query_ids: {}".format(query_ids))
    logging.debug("batch_query_profile_by_ids_cache missing_query_ids: {}".format(missing_query_ids))
    logging.debug("batch_query_profile_by_ids_cache require_update_ids: {}".format(require_update_ids))
    logging.debug("batch_query_profile_by_ids_cache cache_identity_records: {}".format(len(cache_identity_records)))

    final_identity_records = cache_identity_records.copy()
    if missing_query_ids:
        logging.info("missing data")
        missing_identity_records = await query_and_update_missing_query_ids(missing_query_ids)
        final_identity_records.extend(missing_identity_records)

    if require_update_ids:
        logging.info("has olddata and return immediately")
        # Update background
        asyncio.create_task(query_and_update_missing_query_ids(require_update_ids))

    return final_identity_records
