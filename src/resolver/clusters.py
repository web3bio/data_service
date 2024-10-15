#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-12 14:10:05
LastEditors: Zella Zhong
LastEditTime: 2024-10-15 16:38:18
FilePath: /data_service/src/resolver/clusters.py
Description: 
'''
import logging
from datetime import datetime
from sqlalchemy.inspection import inspect
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import load_only
from urllib.parse import unquote

from session import get_session
from model.clusters import ClustersProfile

from utils import convert_camel_case

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


def get_clusters_selected_fields(db_baseclass_name, info):
    attr_names = [c_attr.key for c_attr in inspect(db_baseclass_name).mapper.column_attrs]
    # Extract selected fields from the `info` object
    base_selected_fields = ["cluster_id", "network", "address", "is_verified", "cluster_name", "name", "delete_time"]
    filter_selected_fields = []
    filter_selected_fields.extend(base_selected_fields)
    info_selected_fields = info.selected_fields[0].selections

    for field in info_selected_fields:
        field_name = convert_camel_case(field.name)
        match field_name:
            case "id":
                continue
            case "identity":
                filter_selected_fields.append("cluster_id")
                filter_selected_fields.append("cluster_name")
            case "platform":
                continue
            case "network":
                filter_selected_fields.append("network")
                filter_selected_fields.append("address")
            case "primary_name":
                continue
            case "is_primary":
                continue
            case "resolved_address":
                continue
            case "owner_address":
                filter_selected_fields.append("network")
                filter_selected_fields.append("address")
            case "expired_at":
                continue
            case "profile":
                profile_selected_fields = get_selected_fields("profile", info_selected_fields)
                if profile_selected_fields:
                    for profile_field in profile_selected_fields:
                        profile_field_name = convert_camel_case(profile_field.name)
                        match profile_field_name:
                            case "identity":
                                filter_selected_fields.append("cluster_id")
                                filter_selected_fields.append("cluster_name")
                            case "platform":
                                continue
                            case "address":
                                filter_selected_fields.append("network")
                                filter_selected_fields.append("address")
                            case "display_name":
                                continue
                            case "avatar":
                                filter_selected_fields.append("avatar")
                            case "description":
                                continue
                            case "contenthash":
                                continue
                            case "texts":
                                continue
                            case "addresses":
                                filter_selected_fields.append("network")
                                filter_selected_fields.append("address")
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
                                filter_selected_fields.append("cluster_id")
                                filter_selected_fields.append("cluster_name")
                            case "platform":
                                continue
                            case "network":
                                filter_selected_fields.append("network")
                                filter_selected_fields.append("address")
                            case "primary_name":
                                continue
                            case "is_primary":
                                continue
                            case "resolved_address":
                                continue
                            case "owner_address":
                                filter_selected_fields.append("network")
                                filter_selected_fields.append("address")
                            case "expired_at":
                                continue
                            case "profile":
                                profile_selected_fields = get_selected_fields("profile", info_selected_fields)
                                if profile_selected_fields:
                                    for profile_field in profile_selected_fields:
                                        profile_field_name = convert_camel_case(profile_field.name)
                                        match profile_field_name:
                                            case "identity":
                                                filter_selected_fields.append("cluster_id")
                                                filter_selected_fields.append("cluster_name")
                                            case "platform":
                                                continue
                                            case "address":
                                                filter_selected_fields.append("network")
                                                filter_selected_fields.append("address")
                                            case "display_name":
                                                continue
                                            case "avatar":
                                                filter_selected_fields.append("avatar")
                                            case "description":
                                                continue
                                            case "contenthash":
                                                continue
                                            case "texts":
                                                continue
                                            case "addresses":
                                                filter_selected_fields.append("network")
                                                filter_selected_fields.append("address")
            # If an exact match is not confirmed, this last case will be used if provided
            case _:
                continue

    match_selected_fields = list(set(attr_names) & set(filter_selected_fields))
    # logging.info("Match selected fields: %s", match_selected_fields)
    match_selected_fields = [getattr(db_baseclass_name, f) for f in match_selected_fields]
    return match_selected_fields

async def query_profile_by_single_clusters(info, query_str):
    logging.debug("query_profile_by_single_clusters %s", query_str)
    query_item = query_str.rstrip('/').split('/')
    selected_fields = get_clusters_selected_fields(ClustersProfile, info)
    if len(query_item) == 1:
        clusters_profile_records = []
        query_cluster_name = query_item[0]
        async with get_session() as s:
            if len(selected_fields) > 0:
                profile_sql = select(ClustersProfile).options(
                    load_only(*selected_fields))\
                    .filter(ClustersProfile.cluster_name == query_cluster_name)
                profile_result = await s.execute(profile_sql)
                profile_records = profile_result.scalars().all()
                for row in profile_records:
                    clusters_profile_records.append({key: value for key, value in row.__dict__.items()})

        if len(clusters_profile_records) == 0:
            return None

        cluster_name_dict = {}
        for item in clusters_profile_records:
            platform = Platform.clusters
            cluster_name = item.get('cluster_name', None)
            cluster_id = item.get('cluster_id', 0)
            if cluster_name is None:
                continue
            address = item.get('address', None)
            network = item.get('network', None)
            if cluster_name not in cluster_name_dict:
                cluster_name_profile = Profile(
                    uid=cluster_id,
                    identity=cluster_name,
                    platform=platform,
                    network=network,
                    address=address,
                    display_name=cluster_name,
                    addresses=[],
                    avatar=None,
                    description=None,
                    social=None
                )
                cluster_name_dict[cluster_name] = IdentityRecordSimplified(
                    id=f"{platform.value},{cluster_name}",
                    identity=cluster_name,
                    platform=platform,
                    network=network,
                    primary_name=None,
                    is_primary=False,
                    expired_at=None,
                    resolved_address=[],
                    owner_address=[],
                    profile=cluster_name_profile
                )

            if address != "":
                cluster_name_dict[cluster_name].owner_address.append(
                    Address(
                        address=address,
                        network=network
                    )
                )
                cluster_name_dict[cluster_name].resolved_address.append(
                    Address(
                        address=address,
                        network=network
                    )
                )
                cluster_name_dict[cluster_name].profile.addresses.append(
                    Address(
                        address=address,
                        network=network
                    )
                )

        identity_record = cluster_name_dict.get(query_cluster_name, None)
        return identity_record

    elif len(query_item) > 1:
        name_profile_record = None
        query_cluster_name = query_item[0]
        query_name = query_item[1]
        async with get_session() as s:
            if len(selected_fields) > 0:
                profile_sql = select(ClustersProfile).options(
                    load_only(*selected_fields))\
                    .filter(and_(ClustersProfile.cluster_name == query_cluster_name, ClustersProfile.name == query_name))
                profile_result = await s.execute(profile_sql)
                one_profile_record = profile_result.scalars().one_or_none()
                if one_profile_record is not None:
                    name_profile_record = {key: value for key, value in one_profile_record.__dict__.items()}
        if name_profile_record is None:
            return None

        owner_addresses = []
        resolved_addresses = []
        records = []
        platform = Platform.clusters
        cluster_name = name_profile_record.get('cluster_name', None)
        name = name_profile_record.get('name', None)
        cluster_id = name_profile_record.get('cluster_id', 0)
        if cluster_name is None:
            return None
        if name is None:
            return None

        primary_id = "{},{}/{}".format(platform.value, cluster_name, name)
        identity = "{}/{}".format(cluster_name, name)
        address = name_profile_record.get('address', None)
        network = name_profile_record.get('network', None)
        if address != "":
            owner_addresses.append(
                Address(
                    address=address,
                    network=network
                )
            )
            resolved_addresses.append(
                Address(
                    address=address,
                    network=network
                )
            )
            records.append(
                Address(
                    address=address,
                    network=network
                )
            )

        profile = Profile(
            uid=cluster_id,
            identity=identity,
            platform=platform,
            network=network,
            address=address,
            display_name=identity,
            addresses=records,
            avatar=None,
            description=None,
            social=None
        )
        identity_record = IdentityRecordSimplified(
            id=primary_id,
            identity=identity,
            platform=platform,
            network=network,
            primary_name=None,
            is_primary=False,
            expired_at=None,
            resolved_address=resolved_addresses,
            owner_address=owner_addresses,
            profile=profile
        )
        return identity_record

async def query_profile_by_batch_clusters(info, batch_clusters_name):
    if len(batch_clusters_name) > QUERY_MAX_LIMIT:
        return ExceedRangeInput(QUERY_MAX_LIMIT)

    logging.debug("query_profile_by_batch_clusters %s", batch_clusters_name)
    checked_clusters = []
    for name in batch_clusters_name:
        if name.find('/') == -1:
            # name dont have {cluster_name}/{name}
            checked_clusters.append(name)
        else:
            # only get cluster_name part
            checked_clusters.append(name.split('/')[0])

    selected_fields = get_clusters_selected_fields(ClustersProfile, info)
    profile_dict = {}
    async with get_session() as s:
        if len(selected_fields) > 0:
            profile_sql = select(ClustersProfile).options(
                load_only(*selected_fields))\
                .filter(ClustersProfile.cluster_name.in_(checked_clusters))
            profile_result = await s.execute(profile_sql)
            profile_records = profile_result.scalars().all()
            for row in profile_records:
                unique_id = "{}-{}-{}-{}".format(
                    row.cluster_id, row.network, row.address, row.cluster_name
                )
                profile_dict[unique_id] = {key: value for key, value in row.__dict__.items()}

    result = []
    cluster_name_dict = {}
    for _, item in profile_dict.items():
        owner_addresses = []
        resolved_addresses = []
        records = []
        platform = Platform.clusters
        cluster_name = item.get('cluster_name', None)
        name = item.get('name', None)
        cluster_id = item.get('cluster_id', 0)
        if cluster_name is None:
            continue
        if name is None:
            continue

        address = item.get('address', None)
        network = item.get('network', None)
        if cluster_name not in cluster_name_dict:
            cluster_name_profile = Profile(
                uid=cluster_id,
                identity=cluster_name,
                platform=platform,
                network=network,
                address=address,
                display_name=cluster_name,
                addresses=[],
                avatar=None,
                description=None,
                social=None
            )
            cluster_name_dict[cluster_name] = IdentityRecordSimplified(
                id=f"{platform.value},{cluster_name}",
                identity=cluster_name,
                platform=platform,
                network=network,
                primary_name=None,
                is_primary=False,
                expired_at=None,
                resolved_address=[],
                owner_address=[],
                profile=cluster_name_profile
            )

        primary_id = "{},{}/{}".format(platform.value, cluster_name, name)
        identity = "{}/{}".format(cluster_name, name)
        if address != "":
            owner_addresses.append(
                Address(
                    address=address,
                    network=network
                )
            )
            resolved_addresses.append(
                Address(
                    address=address,
                    network=network
                )
            )
            records.append(
                Address(
                    address=address,
                    network=network
                )
            )
            cluster_name_dict[cluster_name].owner_address.append(
                Address(
                    address=address,
                    network=network
                )
            )
            cluster_name_dict[cluster_name].resolved_address.append(
                Address(
                    address=address,
                    network=network
                )
            )
            cluster_name_dict[cluster_name].profile.addresses.append(
                Address(
                    address=address,
                    network=network
                )
            )

        profile = Profile(
            uid=cluster_id,
            identity=identity,
            platform=platform,
            network=network,
            address=address,
            display_name=identity,
            addresses=records,
            avatar=None,
            description=None,
            social=None
        )
        result.append(IdentityRecordSimplified(
            id=primary_id,
            identity=identity,
            platform=platform,
            network=network,
            primary_name=None,
            is_primary=False,
            expired_at=None,
            resolved_address=[],
            owner_address=owner_addresses,
            profile=profile
        ))

    for _, cluster_name_record in cluster_name_dict.items():
        result.insert(0, cluster_name_record)
    return result
