#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 21:38:55
LastEditors: Zella Zhong
LastEditTime: 2024-10-09 14:48:38
FilePath: /data_service/src/resolver/farcaster.py
Description: 
'''
import logging
from datetime import datetime
from sqlalchemy.inspection import inspect
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import load_only
from urllib.parse import unquote

from session import get_session
from model.farcaster import FarcasterProfile, FarcasterVerified, FarcasterSocial

from utils import check_evm_address, convert_camel_case

from scalar.platform import Platform
from scalar.network import Network, Address, CoinTypeMap
from scalar.identity_graph import IdentityRecordSimplified
from scalar.identity_record import IdentityRecord
from scalar.profile import Profile, SocialProfile
from scalar.error import EmptyInput, ExceedRangeInput


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
            one_profile_record = profile_result.scalars().one()
            if one_profile_record is None:
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
                one_social_record = social_result.scalars().one()
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
    if len(fnames) == 0:
        return EmptyInput()

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
