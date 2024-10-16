#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 18:41:34
LastEditors: Zella Zhong
LastEditTime: 2024-10-16 16:23:03
FilePath: /data_service/src/resolver/ethereum.py
Description: 
'''
import logging
from datetime import datetime
from sqlalchemy.inspection import inspect
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import load_only
from urllib.parse import unquote

from session import get_session
from model import EnsnameModel

from utils import check_evm_address, convert_camel_case

from scalar.platform import Platform
from scalar.network import Network, Address, CoinTypeMap
from scalar.identity_graph import IdentityRecordSimplified
from scalar.identity_record import IdentityRecord
from scalar.profile import Profile
from scalar.error import EmptyInput, EvmAddressInvalid, ExceedRangeInput

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
        texts = {key: unquote(text, 'utf-8') for key, text in texts.items()}
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
    identity_record = IdentityRecord(
        id=f"{Platform.ethereum.value},{checked_address}",
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
    logging.debug("query_profile_by_addresses %s", addresses)
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
                texts = {key: unquote(text, 'utf-8') for key, text in texts.items()}
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
