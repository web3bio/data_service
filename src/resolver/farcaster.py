#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 21:38:55
LastEditors: Zella Zhong
LastEditTime: 2024-10-25 19:18:05
FilePath: /data_service/src/resolver/farcaster.py
Description: 
'''
import random
import logging
from datetime import datetime
from sqlalchemy.inspection import inspect
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import load_only
from urllib.parse import unquote

from session import get_session
from model.farcaster import FarcasterProfile, FarcasterVerified, FarcasterSocial, FarcasterFnames
from cache.redis import RedisClient

from utils import convert_camel_case
from utils.address import is_ethereum_address, is_base58_solana_address
from utils.timeutils import get_unix_microseconds

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


async def get_fids_by_input(ids):
    final_fids = set()
    fnames = []
    verified_addresses = []
    for query_id in ids:
        if query_id.startswith('#'):
            try:
                query_fid = query_id.lstrip('#')
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
        redis_client = await RedisClient.get_instance()
        aliases_value = await redis_client.mget(*query_ids)
    except Exception as ex:
        logging.exception(ex)
        # if cache logic is failed, just return query_from_db immediately
        return [], [], query_ids

async def set_farcaster_profile_to_cache(cache_identity_record: IdentityRecordSimplified, expire_window):
    random_offset = random.randint(0, 30 * 60)  # Adding up to 30 minutes of randomness
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


async def batch_query_profile_by_fids_db(fids):
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


async def batch_query_profile_by_ids_cache(info, ids, require_cache=False):
    if len(ids) > QUERY_MAX_LIMIT:
        return ExceedRangeInput(QUERY_MAX_LIMIT)

    identity_records = []
    if require_cache is False:
        # query data from db and return immediately
        fids = await get_fids_by_input(ids)
        logging.debug("batch_query_profile_by_ids_cache input %s turn to fids: %s", ids, fids)
        identity_records = await batch_query_profile_by_fids_db(fids)
        return identity_records

    # require_cache is True:
    # fids = await get_fids_by_input(ids)
    # logging.debug("batch_query_profile_by_ids_cache input %s turn to fids: %s", ids, fids)

