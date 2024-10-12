#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 19:05:41
LastEditors: Zella Zhong
LastEditTime: 2024-10-12 16:35:29
FilePath: /data_service/src/resolver/fetch.py
Description: 
'''
import asyncio
import logging
from scalar.platform import Platform
from scalar.error import PlatformNotSupport

from resolver.ethereum import query_profile_by_addresses, query_profile_by_single_address
from resolver.ensname import query_profile_by_ensnames, query_profile_by_single_ensname
from resolver.farcaster import query_profile_by_fnames, query_profile_by_single_fname
from resolver.lens import query_profile_by_lens_handle, query_profile_by_single_lens_handle
from resolver.solana import query_profile_by_solana_addresses, query_profile_by_single_solana
from resolver.clusters import query_profile_by_batch_clusters, query_profile_by_single_clusters

from resolver.bitcoin import query_profile_by_bitcoin_addresses, query_profile_by_single_bitcoin
from resolver.litecoin import query_profile_by_litecoin_addresses, query_profile_by_single_litecoin
from resolver.dogecoin import query_profile_by_dogecoin_addresses, query_profile_by_single_dogecoin
from resolver.aptos import query_profile_by_aptos_addresses, query_profile_by_single_aptos
from resolver.stacks import query_profile_by_stacks_addresses, query_profile_by_single_stacks
from resolver.tron import query_profile_by_tron_addresses, query_profile_by_single_tron
from resolver.ton import query_profile_by_ton_addresses, query_profile_by_single_ton
from resolver.xrpc import query_profile_by_xrpc_addresses, query_profile_by_single_xrpc
from resolver.cosmos import query_profile_by_cosmos_addresses, query_profile_by_single_cosmos



async def batch_fetch(info, platform, identities):
    if platform == Platform.ethereum:
        return await query_profile_by_addresses(info, identities)
    elif platform == Platform.ens:
        return await query_profile_by_ensnames(info, identities)
    elif platform == Platform.farcaster:
        return await query_profile_by_fnames(info, identities)
    elif platform == Platform.lens:
        return await query_profile_by_lens_handle(info, identities)
    elif platform == Platform.solana:
        return await query_profile_by_solana_addresses(info, identities)
    elif platform == Platform.clusters:
        return await query_profile_by_batch_clusters(info, identities)
    elif platform == Platform.bitcoin:
        return await query_profile_by_bitcoin_addresses(info, identities)
    elif platform == Platform.litecoin:
        return await query_profile_by_litecoin_addresses(info, identities)
    elif platform == Platform.dogecoin:
        return await query_profile_by_dogecoin_addresses(info, identities)
    elif platform == Platform.aptos:
        return await query_profile_by_aptos_addresses(info, identities)
    elif platform == Platform.stacks:
        return await query_profile_by_stacks_addresses(info, identities)
    elif platform == Platform.tron:
        return await query_profile_by_tron_addresses(info, identities)
    elif platform == Platform.ton:
        return await query_profile_by_ton_addresses(info, identities)
    elif platform == Platform.xrpc:
        return await query_profile_by_xrpc_addresses(info, identities)
    elif platform == Platform.cosmos:
        return await query_profile_by_cosmos_addresses(info, identities)
    else:
        return PlatformNotSupport(platform)


async def single_fetch(info, platform, identity):
    if platform == Platform.ethereum:
        return await query_profile_by_single_address(info, identity)
    elif platform == Platform.ens:
        return await query_profile_by_single_ensname(info, identity)
    elif platform == Platform.farcaster:
        return await query_profile_by_single_fname(info, identity)
    elif platform == Platform.lens:
        return await query_profile_by_single_lens_handle(info, identity)
    elif platform == Platform.solana:
        return await query_profile_by_single_solana(info, identity)
    elif platform == Platform.clusters:
        return await query_profile_by_single_clusters(info, identity)
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

async def batch_fetch_all(info, vertices_map):
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
