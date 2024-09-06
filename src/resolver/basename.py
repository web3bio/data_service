import logging
from datetime import datetime
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import load_only
from urllib.parse import unquote

from session import get_session
from utils import get_only_selected_fields, check_valid_data, compute_namehash_nowrapped, \
    check_evm_address
from model import BasenameModel
from scalar import Domain
from scalar.error import DomainInvalid, DomainNotFound, EvmAddressInvalid


async def query_basenames_by_name(info, name):
    if not name.endswith("base.eth"):
        return DomainInvalid(name)
    query_namenode = compute_namehash_nowrapped(name)
    logging.info("query_basenames_by_name basenames={}, namenode={}".format(name, query_namenode))
    selected_fields = get_only_selected_fields(BasenameModel, info)
    async with get_session() as s:
        sql = select(BasenameModel).options(load_only(*selected_fields)) \
            .filter(and_(BasenameModel.namenode == query_namenode, BasenameModel.name.is_not(None)))\
            .order_by(BasenameModel.id)
        db_lists = (await s.execute(sql)).scalars().unique().all()

    domains = []
    for d in db_lists:
        basename_dict = check_valid_data(d, BasenameModel)
        if "key_value" in basename_dict:
            if basename_dict["key_value"] is not None:
                for key, text in basename_dict["key_value"].items():
                    basename_dict["key_value"][key] = unquote(text, 'utf-8')
        domains.append(Domain(**basename_dict))

    return domains

async def query_basenames_by_owner(info, addr):
    if not check_evm_address(addr):
        return EvmAddressInvalid(addr)
    logging.info("query_basenames_by_owner owner={}".format(addr))
    selected_fields = get_only_selected_fields(BasenameModel, info)
    async with get_session() as s:
        sql = select(BasenameModel).options(load_only(*selected_fields)) \
            .filter(and_(BasenameModel.owner == addr, BasenameModel.name.is_not(None)))\
            .order_by(BasenameModel.id)
        # sql = select(BasenameModel).options(load_only(*selected_fields)) \
        #     .filter(BasenameModel.owner == addr) \
        #     .filter(BasenameModel.name.is_not(None)) \
        #     .order_by(BasenameModel.id)
        db_lists = (await s.execute(sql)).scalars().unique().all()

    domains = []
    for d in db_lists:
        basename_dict = check_valid_data(d, BasenameModel)
        if "key_value" in basename_dict:
            if basename_dict["key_value"] is not None:
                for key, text in basename_dict["key_value"].items():
                    basename_dict["key_value"][key] = unquote(text, 'utf-8')
        domains.append(Domain(**basename_dict))

    return domains

async def basename_domain_query(info, name):
    if not name.endswith("base.eth"):
        return DomainInvalid(name)
    query_namenode = compute_namehash_nowrapped(name)
    logging.info("basename_domain_query basenames={}, namenode={}".format(name, query_namenode))
    selected_fields = get_only_selected_fields(BasenameModel, info)
    async with get_session() as s:
        sql = select(BasenameModel).options(load_only(*selected_fields)) \
        .filter(BasenameModel.namenode == query_namenode)
        db_result = (await s.execute(sql)).scalars().unique().one()

    if db_result is None:
        return DomainNotFound(name)

    basename_dict = check_valid_data(db_result, BasenameModel)
    if "key_value" in basename_dict:
        if basename_dict["key_value"] is not None:
            for key, text in basename_dict["key_value"].items():
                basename_dict["key_value"][key] = unquote(text, 'utf-8')
    return Domain(**basename_dict)
