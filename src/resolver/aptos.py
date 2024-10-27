#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-12 16:24:59
LastEditors: Zella Zhong
LastEditTime: 2024-10-26 03:18:27
FilePath: /data_service/src/resolver/aptos.py
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
from scalar.network import Network
from scalar.identity_graph import IdentityRecordSimplified
from scalar.identity_record import IdentityRecord
from scalar.profile import Profile
from scalar.error import EmptyInput, EvmAddressInvalid, ExceedRangeInput

QUERY_MAX_LIMIT = 200


async def query_profile_by_single_aptos(info, address):
    address_primary_id = f"{Platform.aptos.value},{address}"
    aliases = [address_primary_id]
    identity_record = IdentityRecord(
        id=address_primary_id,
        aliases=aliases,
        identity=address,
        platform=Platform.aptos,
        network=Network.aptos,
        primary_name=None,
        is_primary=False,
        profile=None
    )
    return identity_record

async def query_profile_by_aptos_addresses(info, addresses):
    if len(addresses) > QUERY_MAX_LIMIT:
        return ExceedRangeInput(QUERY_MAX_LIMIT)

    logging.debug("query_profile_by_aptos_addresses %s", addresses)
    result = []
    for addr in addresses:
        address_primary_id = f"{Platform.aptos.value},{addr}"
        aliases = [address_primary_id]
        result.append(IdentityRecordSimplified(
            id=address_primary_id,
            aliases=aliases,
            identity=addr,
            platform=Platform.aptos,
            network=Network.aptos,
            primary_name=None,
            is_primary=False,
            profile=None
        ))

    return result
