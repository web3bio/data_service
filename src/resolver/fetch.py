#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 19:05:41
LastEditors: Zella Zhong
LastEditTime: 2024-11-01 12:04:23
FilePath: /data_service/src/resolver/fetch.py
Description: 
'''
import asyncio
import logging
from scalar.platform import Platform
from scalar.network import Network
from scalar.error import PlatformNotSupport
from scalar.identity_record import IdentityRecord

from resolver.ethereum import query_profile_by_addresses, query_profile_by_single_address
from resolver.ensname import query_profile_by_ensnames, query_profile_by_single_ensname
from resolver.farcaster import query_profile_by_fnames, query_profile_by_single_fname
from resolver.lens import query_profile_by_lens_handle, query_profile_by_single_lens_handle
from resolver.solana import query_profile_by_solana_addresses, query_profile_by_single_solana
from resolver.clusters import query_profile_by_batch_clusters, query_profile_by_single_clusters
from resolver.basenames import query_profile_by_basenames, query_profile_by_single_basenames

from resolver.bitcoin import query_profile_by_bitcoin_addresses, query_profile_by_single_bitcoin
from resolver.litecoin import query_profile_by_litecoin_addresses, query_profile_by_single_litecoin
from resolver.dogecoin import query_profile_by_dogecoin_addresses, query_profile_by_single_dogecoin
from resolver.aptos import query_profile_by_aptos_addresses, query_profile_by_single_aptos
from resolver.stacks import query_profile_by_stacks_addresses, query_profile_by_single_stacks
from resolver.tron import query_profile_by_tron_addresses, query_profile_by_single_tron
from resolver.ton import query_profile_by_ton_addresses, query_profile_by_single_ton
from resolver.xrpc import query_profile_by_xrpc_addresses, query_profile_by_single_xrpc
from resolver.cosmos import query_profile_by_cosmos_addresses, query_profile_by_single_cosmos


from resolver.farcaster import query_farcaster_profile_by_ids_cache
from resolver.lens import query_lens_profile_by_ids_cache
from resolver.ethereum import query_ethereum_profile_by_ids_cache
from resolver.ensname import query_ensname_profile_by_ids_cache
from resolver.unstoppabledomains import query_unstoppabledomains_profile_by_ids_cache
from resolver.basenames import query_basenames_profile_by_ids_cache

async def single_fetch(info, platform, identity):
    identity_records = []
    address_list = []
    if platform == Platform.ethereum:
        # return await query_profile_by_single_address(info, identity)
        identity_records = await query_ethereum_profile_by_ids_cache(info, [identity], require_cache=True)
    elif platform == Platform.ens:
        # return await query_profile_by_single_ensname(info, identity)
        identity_records = await query_ensname_profile_by_ids_cache(info, [identity], require_cache=True)
    elif platform == Platform.farcaster:
        # return await query_profile_by_single_fname(info, identity)
        identity_records = await query_farcaster_profile_by_ids_cache(info, [identity], require_cache=True)
    elif platform == Platform.lens:
        # return await query_profile_by_single_lens_handle(info, identity)
        identity_records = await query_lens_profile_by_ids_cache(info, [identity], require_cache=True)
    elif platform == Platform.solana:
        record = await query_profile_by_single_solana(info, identity)
        identity_records.append(record)
    elif platform == Platform.clusters:
        record = await query_profile_by_single_clusters(info, identity)
        identity_records.append(record)
    elif platform == Platform.basenames:
        # record = await query_profile_by_single_basenames(info, identity)
        # identity_records.append(record)
        identity_records = await query_basenames_profile_by_ids_cache(info, [identity], require_cache=True)
    elif platform == Platform.unstoppabledomains:
        identity_records = await query_unstoppabledomains_profile_by_ids_cache(info, [identity], require_cache=True)
    elif platform == Platform.bitcoin:
        return await query_profile_by_single_bitcoin(info, identity)
    elif platform == Platform.litecoin:
        return await query_profile_by_single_litecoin(info, identity)
    elif platform == Platform.dogecoin:
        return await query_profile_by_single_dogecoin(info, identity)
    elif platform == Platform.aptos:
        return await query_profile_by_single_aptos(info, identity)
    elif platform == Platform.stacks:
        return await query_profile_by_single_stacks(info, identity)
    elif platform == Platform.tron:
        return await query_profile_by_single_tron(info, identity)
    elif platform == Platform.ton:
        return await query_profile_by_single_ton(info, identity)
    elif platform == Platform.xrpc:
        return await query_profile_by_single_xrpc(info, identity)
    elif platform == Platform.cosmos:
        return await query_profile_by_single_cosmos(info, identity)
    else:
        return PlatformNotSupport(platform)

    if not identity_records:
        return None

    one = identity_records[0]
    identity_record = IdentityRecord(
        id=one.id,
        aliases=one.aliases,
        identity=one.identity,
        platform=one.platform,
        network=one.network,
        primary_name=one.primary_name,
        is_primary=one.is_primary,
        resolved_address=one.resolved_address,
        owner_address=one.owner_address,
        expired_at=one.expired_at,
        updated_at=one.updated_at,
        profile=one.profile,
    )

    address_list = []
    if platform == Platform.ethereum:
        address_list.append(identity_record.identity)
    elif platform == Platform.ens:
        if len(identity_record.resolved_address) == 0:
            if len(identity_record.owner_address) > 0:
                address_list.append(identity_record.owner_address[0].address)
        else:
            address_list.append(identity_record.resolved_address[0].address)
    elif platform == Platform.farcaster:
        if len(identity_record.owner_address) > 0:
            for address_record in identity_record.owner_address:
                if address_record.network == Network.ethereum:
                    address_list.append(address_record.address)
    elif platform == Platform.lens:
        if len(identity_record.owner_address) > 0:
            for address_record in identity_record.owner_address:
                address_list.append(address_record.address)
    elif platform == Platform.clusters:
        if len(identity_record.owner_address) > 0:
            for address_record in identity_record.owner_address:
                if address_record.network == Network.ethereum:
                    address_list.append(address_record.address)
    elif platform == Platform.basenames:
        if len(identity_record.resolved_address) == 0:
            if len(identity_record.owner_address) > 0:
                address_list.append(identity_record.owner_address[0].address)
        else:
            address_list.append(identity_record.resolved_address[0].address)
    if platform != Platform.unstoppabledomains:
        # online fetch: unstoppabledomains data needs to be fetched again
        logging.info("online fetch: unstoppabledomains data needs to be fetched again %s", address_list)
        await query_unstoppabledomains_profile_by_ids_cache(info, address_list, require_cache=True)

    return identity_record

async def fetch_identity_graph_vertices(info, vertices_map):
    tasks = []

    # Prepare the tasks
    for platform, identities in vertices_map.items():
        try:
            platform_enum = Platform[platform]
        except KeyError:
            return PlatformNotSupport(platform)

        if platform_enum == Platform.ethereum:
            tasks.append(query_profile_by_addresses(info, identities))
        elif platform_enum == Platform.ens:
            tasks.append(query_profile_by_ensnames(info, identities))
        elif platform_enum == Platform.farcaster:
            tasks.append(query_profile_by_fnames(info, identities))
        elif platform_enum == Platform.lens:
            tasks.append(query_profile_by_lens_handle(info, identities))
        elif platform_enum == Platform.solana:
            tasks.append(query_profile_by_solana_addresses(info, identities))
        elif platform_enum == Platform.clusters:
            tasks.append(query_profile_by_batch_clusters(info, identities))
        elif platform_enum == Platform.basenames:
            tasks.append(query_profile_by_basenames(info, identities))
        elif platform_enum == Platform.bitcoin:
            tasks.append(query_profile_by_bitcoin_addresses(info, identities))
        elif platform_enum == Platform.litecoin:
            tasks.append(query_profile_by_litecoin_addresses(info, identities))
        elif platform_enum == Platform.dogecoin:
            tasks.append(query_profile_by_dogecoin_addresses(info, identities))
        elif platform_enum == Platform.aptos:
            tasks.append(query_profile_by_aptos_addresses(info, identities))
        elif platform_enum == Platform.stacks:
            tasks.append(query_profile_by_stacks_addresses(info, identities))
        elif platform_enum == Platform.tron:
            tasks.append(query_profile_by_tron_addresses(info, identities))
        elif platform_enum == Platform.ton:
            tasks.append(query_profile_by_ton_addresses(info, identities))
        elif platform_enum == Platform.xrpc:
            tasks.append(query_profile_by_xrpc_addresses(info, identities))
        elif platform_enum == Platform.cosmos:
            tasks.append(query_profile_by_cosmos_addresses(info, identities))
        else:
            logging.warning(f"Unsupported platform: {platform}")

    # Run all tasks concurrently
    results = await asyncio.gather(*tasks)

    # Collect and merge the results
    vertices = []
    for result in results:
        vertices.extend(result)

    return vertices


async def batch_fetch_all(info, vertices_map):
    tasks = []

    # Prepare the tasks
    for platform, identities in vertices_map.items():
        try:
            platform_enum = Platform[platform]
        except KeyError:
            return PlatformNotSupport(platform)

        if platform_enum == Platform.ethereum:
            # tasks.append(query_profile_by_addresses(info, identities))
            tasks.append(query_ethereum_profile_by_ids_cache(info, identities, require_cache=True))
        elif platform_enum == Platform.ens:
            # tasks.append(query_profile_by_ensnames(info, identities))
            tasks.append(query_ensname_profile_by_ids_cache(info, identities, require_cache=True))
        elif platform_enum == Platform.farcaster:
            # tasks.append(query_profile_by_fnames(info, identities))
            tasks.append(query_farcaster_profile_by_ids_cache(info, identities, require_cache=True))
        elif platform_enum == Platform.lens:
            # tasks.append(query_profile_by_lens_handle(info, identities))
            tasks.append(query_lens_profile_by_ids_cache(info, identities, require_cache=True))
        elif platform_enum == Platform.clusters:
            tasks.append(query_profile_by_batch_clusters(info, identities))
        elif platform_enum == Platform.basenames:
            # tasks.append(query_profile_by_basenames(info, identities))
            tasks.append(query_basenames_profile_by_ids_cache(info, identities, require_cache=True))
        elif platform_enum == Platform.solana:
            tasks.append(query_profile_by_solana_addresses(info, identities))
        elif platform_enum == Platform.unstoppabledomains:
            tasks.append(query_unstoppabledomains_profile_by_ids_cache(info, identities, require_cache=True))
        elif platform_enum == Platform.bitcoin:
            tasks.append(query_profile_by_bitcoin_addresses(info, identities))
        elif platform_enum == Platform.litecoin:
            tasks.append(query_profile_by_litecoin_addresses(info, identities))
        elif platform_enum == Platform.dogecoin:
            tasks.append(query_profile_by_dogecoin_addresses(info, identities))
        elif platform_enum == Platform.aptos:
            tasks.append(query_profile_by_aptos_addresses(info, identities))
        elif platform_enum == Platform.stacks:
            tasks.append(query_profile_by_stacks_addresses(info, identities))
        elif platform_enum == Platform.tron:
            tasks.append(query_profile_by_tron_addresses(info, identities))
        elif platform_enum == Platform.ton:
            tasks.append(query_profile_by_ton_addresses(info, identities))
        elif platform_enum == Platform.xrpc:
            tasks.append(query_profile_by_xrpc_addresses(info, identities))
        elif platform_enum == Platform.cosmos:
            tasks.append(query_profile_by_cosmos_addresses(info, identities))
        else:
            logging.warning(f"Unsupported platform: {platform}")

    # Run all tasks concurrently
    results = await asyncio.gather(*tasks)

    # Collect and merge the results
    vertices = []
    for result in results:
        vertices.extend(result)

    return vertices
