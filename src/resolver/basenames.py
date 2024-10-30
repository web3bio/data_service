#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-09-06 15:40:40
LastEditors: Zella Zhong
LastEditTime: 2024-10-30 15:03:31
FilePath: /data_service/src/resolver/basenames.py
Description: 
'''
import logging
from datetime import datetime
from sqlalchemy.inspection import inspect
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import load_only
from urllib.parse import unquote

from session import get_session
from model import BasenameModel

from utils import check_evm_address, convert_camel_case, compute_namehash_nowrapped

from scalar.platform import Platform
from scalar.network import Network, Address, CoinTypeMap
from scalar.identity_graph import IdentityRecordSimplified
from scalar.identity_record import IdentityRecord
from scalar.profile import Profile
from scalar.error import DomainNotFound, EmptyInput, EvmAddressInvalid, ExceedRangeInput


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
