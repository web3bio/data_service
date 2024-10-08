#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 19:05:41
LastEditors: Zella Zhong
LastEditTime: 2024-10-07 23:24:02
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

async def batch_fetch(info, platform, identities):
    if platform == Platform.ethereum:
        result = await query_profile_by_addresses(info, identities)
        return result
    elif platform == Platform.ens:
        result = await query_profile_by_ensnames(info, identities)
        return result
    elif platform == Platform.farcaster:
        result = await query_profile_by_fnames(info, identities)
        return result
    elif platform == Platform.lens:
        result = await query_profile_by_lens_handle(info, identities)
        return result
    else:
        return PlatformNotSupport(platform)


async def single_fetch(info, platform, identity):
    if platform == Platform.ethereum:
        result = await query_profile_by_single_address(info, identity)
        return result
    elif platform == Platform.ens:
        result = await query_profile_by_single_ensname(info, identity)
        return result
    elif platform == Platform.farcaster:
        result = await query_profile_by_single_fname(info, identity)
        return result
    elif platform == Platform.lens:
        result = await query_profile_by_single_lens_handle(info, identity)
        return result
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
        else:
            logging.warning(f"Unsupported platform: {platform}")

    # Run all tasks concurrently
    results = await asyncio.gather(*tasks)

    # Collect and merge the results
    vertices = []
    for result in results:
        vertices.extend(result)

    return vertices
