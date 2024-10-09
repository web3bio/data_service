#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-07 01:31:36
LastEditors: Zella Zhong
LastEditTime: 2024-10-09 13:29:42
FilePath: /data_service/src/resolver/lens.py
Description: 
'''
import logging
from datetime import datetime
from sqlalchemy.inspection import inspect
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import load_only
from urllib.parse import unquote

from session import get_session
from model.lens import LensV2Profile, LensV2Social

from utils import check_evm_address, convert_camel_case

from scalar.platform import Platform
from scalar.network import Network, Address
from scalar.coin_type import CoinType, Record
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
                                            case "update_at":
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
                                                            case "update_at":
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
            one_profile_record = profile_result.scalars().one()
            if one_profile_record is not None:
                profile_id = one_profile_record.profile_id
                profile_record = {key: value for key, value in one_profile_record.__dict__.items()}

        if len(social_fields) > 0:
            if profile_id is not None:
                social_sql = select(LensV2Social).options(
                    load_only(*social_fields))\
                    .filter(LensV2Social.profile_id == profile_id)
                social_result = await s.execute(social_sql)
                one_social_record = social_result.scalars().one()
                if one_social_record is not None:
                    social_record = {key: value for key, value in one_social_record.__dict__.items()}

    if profile_record is None:
        return None

    network = None
    resolved_address = []
    owner_address = []
    records = []
    address = profile_record.get('address', None)
    if address is not None:
        network = Network.ethereum
        resolved_address.append(Address(address=address, network=network))
        owner_address.append(Address(address=address, network=network))
        records.append(Record(address=address, coin_type=CoinType.eth))

    name = profile_record.get('name', None)
    if name is None:
        return None

    texts = profile_record.get('texts', {})
    if texts:
        texts = {key: unquote(text, 'utf-8') for key, text in texts.items()}
    else:
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
            update_at=social_record.get('update_time', None),
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
    if len(names) == 0:
        return EmptyInput()

    if len(names) > QUERY_MAX_LIMIT:
        return ExceedRangeInput(QUERY_MAX_LIMIT)

    logging.debug("query_profile_by_lens_handle %s", names)
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
            records.append(Record(address=address, coin_type=CoinType.eth))

        name = profile_record.get('name', None)
        if name is None:
            continue

        texts = profile_record.get('texts', {})
        if texts:
            texts = {key: unquote(text, 'utf-8') for key, text in texts.items()}
        else:
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
                        update_at=social_info.get('update_time', None),
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
