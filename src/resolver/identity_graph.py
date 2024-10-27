#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-07 03:10:41
LastEditors: Zella Zhong
LastEditTime: 2024-10-26 02:59:25
FilePath: /data_service/src/resolver/identity_graph.py
Description: 
'''
import asyncio
import aiohttp
import json
import logging

from datetime import datetime
from sqlalchemy.inspection import inspect
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import load_only
from urllib.parse import unquote

import setting
from session import get_session
from model import EnsnameModel

from utils import check_evm_address, convert_camel_case, compute_namehash_nowrapped

from scalar.platform import Platform
from scalar.network import Network
from scalar.data_source import DataSource
from scalar.identity_graph import IdentityRecordSimplified
from scalar.profile import Profile
from scalar.identity_graph import IdentityGraph
from scalar.identity_connection import IdentityConnection, EdgeType
from scalar.error import GraphDBException


from .fetch import batch_fetch_all


async def find_identity_graph(info, self_platform, self_identity):
    '''
    description:
    find_identity_graph query:
    curl -X GET 'http://hostname:restpp_port/restpp/query/SocialGraph/find_identity_graph?platform=VALUE&identity&[reverse_flag=VALUE]
    '''
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + setting.TIGERGRAPH_SETTINGS["social_graph_token"]
    }

    query_url = "http://{}:{}/restpp/query/{}/find_identity_graph?platform={}&identity={}&reverse_flag=0".format(
        setting.TIGERGRAPH_SETTINGS["host"],
        setting.TIGERGRAPH_SETTINGS["restpp"],
        setting.TIGERGRAPH_SETTINGS["social_graph_name"],
        self_platform,
        self_identity
    )
    logging.info("find_identity_graph %s", query_url)
    vertices = []
    vertices_map = {}
    edges = []
    graph_id = None
    async with aiohttp.ClientSession() as session:
        async with session.get(url=query_url, headers=headers, timeout=60) as response:
            raw_text = await response.text()
            res = json.loads(raw_text)

            if "error" in res and res["error"] is True:
                error_msg = "graphdb find_identity_graph[{},{}] failed:, error={}".format(self_platform, self_identity, res)
                logging.error(error_msg)
                return GraphDBException(error_msg)

            results = res.get("results", [])
            if len(results) > 0:
                result = results[0]
                graph_id = result["graph_id"]
                for v in result["vertices"]:
                    # vertices.append(IdentityRecordSimplified(
                    #     id=v["id"],
                    #     platform=Platform[v["platform"]],
                    #     identity=v["identity"]
                    # ))
                    platform = v["platform"]
                    identity = v["identity"]
                    if platform not in vertices_map:
                        vertices_map[platform] = []
                    vertices_map[platform].append(identity)

                for e in result["edges"]:
                    edges.append(IdentityConnection(
                        edge_type=e["edge_type"],
                        data_source=e["data_source"],
                        source=e["source_v"],
                        target=e["target_v"]
                    ))

    if graph_id is None:
        return None

    # vertices and edges, replace with batch query
    # Notice:
    # Use asyncio.gather, which allows run multiple asynchronous tasks in parallel.
    # This method can avoid sequentially awaiting each query and instead run them all concurrently, 
    # making the process more efficient.
    vertices = batch_fetch_all(info, vertices_map)

    identity_graph = IdentityGraph(graph_id=graph_id, vertices=vertices, edges=edges)
    return identity_graph
