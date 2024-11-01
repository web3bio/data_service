#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-11-01 04:24:35
LastEditors: Zella Zhong
LastEditTime: 2024-11-01 05:47:21
FilePath: /data_service/src/graphdb/identity_graph.py
Description: 
'''
import asyncio
import aiohttp
import copy
import json
import random
import logging
import setting

from urllib.parse import unquote, quote

from scalar.error import GraphDBException

VERTEX_IDENTITY = "Identities"
VERTEX_IDENTITY_GRAPH = "IdentitiesGraph"

EDGE_PART_OF_IDENTITY_GRAPH = "PartOfIdentitiesGraph"
EDGE_HOLD = "Hold"
EDGE_PROOF = "Proof_Forward"
EDGE_RESOLVE = "Resolve"
EDGE_REVERSE_RESOLVE = "Reverse_Resolve"


class Vertex:
    '''Vertex'''
    def __init__(self, vertex_id, vertex_type, attributes):
        self.vertex_id = vertex_id
        self.vertex_type = vertex_type
        self.attributes = attributes


class Edge:
    '''Edge'''
    def __init__(self, edge_type, from_id, from_type, to_id, to_type, attributes):
        self.edge_type = edge_type
        self.from_id = from_id
        self.from_type = from_type
        self.to_id = to_id
        self.to_type = to_type
        self.attributes = attributes


async def upsert_graph(vertices, edges):
    '''
    description:
    {
        "vertices": {
            "<vertex_type>": {
                "<vertex_id>": {
                    "<attribute>": {
                        "value": < value > ,
                        "op": < opcode >
                    }
                }
            }
        },
        "edges": {
            "<source_vertex_type>": {
                "<source_vertex_id>": {
                    "<edge_type>": {
                        "<target_vertex_type>": {
                            "<target_vertex_id>": {
                                "<attribute>": {
                                    "value": < value > ,
                                    "op": < opcode >
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return {*}
    '''
    graph_req = {}
    if len(vertices) > 0:
        graph_req["vertices"] = {}
    for v in vertices:
        vertex_type = v.vertex_type
        vertex_id = v.vertex_id
        if vertex_type not in graph_req["vertices"]:
            graph_req["vertices"][vertex_type] = {}
        graph_req["vertices"][vertex_type][vertex_id] = v.attributes

    if len(edges) > 0:
        graph_req["edges"] = {}

    for e in edges:
        if e.from_type not in graph_req["edges"]:
            graph_req["edges"][e.from_type] = {}
        if e.from_id not in graph_req["edges"][e.from_type]:
            graph_req["edges"][e.from_type][e.from_id] = {}
        if e.edge_type not in graph_req["edges"][e.from_type][e.from_id]:
            graph_req["edges"][e.from_type][e.from_id][e.edge_type] = {}
        if e.to_type not in graph_req["edges"][e.from_type][e.from_id][e.edge_type]:
            graph_req["edges"][e.from_type][e.from_id][e.edge_type][e.to_type] = {}

        graph_req["edges"][e.from_type][e.from_id][e.edge_type][e.to_type][e.to_id] = e.attributes

    payload = json.dumps(graph_req)
    # logging.debug(payload)

    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + setting.TIGERGRAPH_SETTINGS["social_graph_token"]
    }
    upsert_url = "http://{}:{}/restpp/graph/{}?vertex_must_exist=true".format(
        setting.TIGERGRAPH_SETTINGS["host"],
        setting.TIGERGRAPH_SETTINGS["restpp"],
        setting.TIGERGRAPH_SETTINGS["social_graph_name"])
    async with aiohttp.ClientSession() as session:
        async with session.post(url=upsert_url, data=payload, headers=headers, timeout=60) as response:
            if response.status != 200:
                error_msg = "tigergraph upsert failed: url={}, {} {}".format(
                    upsert_url, response.status, response.reason)
                logging.error(error_msg)
                raise Exception(error_msg)

            response_text = await response.text()
            res = json.loads(response_text)
            if "error" in res:
                if res["error"] is True:
                    error_msg = "tigergraph upsert failed: url={}, error={}".format(upsert_url, res)
                    logging.warn(error_msg)
                    raise Exception(error_msg)

    logging.debug("tigergraph upsert res: {}".format(res))


async def delete_edge(session, delete_url, headers, encoded_vid, edge_type):
    try:
        async with session.delete(url=delete_url, headers=headers, timeout=60) as response:
            if response.status != 200:
                error_msg = f"tigergraph delete_all_edges_by_source failed: url={delete_url}, {response.status} {response.reason}"
                logging.error(error_msg)
                response_text = await response.text()
                logging.error(f"tigergraph delete_all_edges_by_source failed response content: {response_text}")
                raise Exception(error_msg)
            
            # Read the response text
            raw_text = await response.text()
            # Optionally parse JSON response if needed
            res = json.loads(raw_text)
            if "error" in res and res["error"] is True:
                error_msg = f"tigergraph delete_all_edges_by_source failed: url={delete_url}, error={res}"
                logging.warning(error_msg)

            logging.debug(f"Successfully deleted edges: {encoded_vid}/{edge_type}")

    except aiohttp.ClientError as e:
        logging.error(f"Network error occurred: {e}")
        raise

async def delete_all_edges_by_source(edge_types, source_vertex_ids):
    """
    Delete all edges from specified source vertex IDs for given edge types in TigerGraph.

    Args:
        edge_types (list): List of edge types to delete.
        source_vertex_ids (list): List of source vertex IDs.
    """
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + setting.TIGERGRAPH_SETTINGS["social_graph_token"]
    }

    async with aiohttp.ClientSession() as session:
        # Collect all the tasks for concurrent execution
        tasks = []
        for vid in source_vertex_ids:
            for edge_type in edge_types:
                encoded_vid = quote(vid, 'utf-8')  # Convert string to URL-encoded
                delete_url = "http://{}:{}/restpp/graph/{}/edges/Identities/{}/{}".format(
                    setting.TIGERGRAPH_SETTINGS["host"],
                    setting.TIGERGRAPH_SETTINGS["restpp"],
                    setting.TIGERGRAPH_SETTINGS["social_graph_name"],
                    encoded_vid, edge_type
                )
                # Create a task for each delete request
                tasks.append(delete_edge(session, delete_url, headers, encoded_vid, edge_type))

        # Run all tasks concurrently
        await asyncio.gather(*tasks)

# deadcode
async def delete_all_edges_by_source_forloop(edge_types, source_vertex_ids):
    '''
    Delete all edges from specified source vertex IDs for given edge types in TigerGraph.

    Args:
        edge_types (list): List of edge types to delete.
        source_vertex_ids (list): List of source vertex IDs.

    Provide only the source to delete all edges from that source, 
    or the source ID and a target type only without the target ID.

    e.g. Delete all transfers from account 24601
    curl -s -X DELETE 'http://localhost:14240/restpp/graph/{graph_name}/edges/{VertexType}/{VertexId}/{EdgeType}' | jq .
    '''
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + setting.TIGERGRAPH_SETTINGS["social_graph_token"]
    }
    async with aiohttp.ClientSession() as session:
        for vid in source_vertex_ids:
            for edge_type in edge_types:
                encoded_vid = quote(vid, 'utf-8')  # convert string to url-encoded
                delete_url = "http://{}:{}/restpp/graph/{}/edges/Identities/{}/{}".format(
                    setting.TIGERGRAPH_SETTINGS["host"],
                    setting.TIGERGRAPH_SETTINGS["restpp"],
                    setting.TIGERGRAPH_SETTINGS["social_graph_name"],
                    encoded_vid, edge_type)

                try:
                    async with session.delete(url=delete_url, headers=headers, timeout=60) as response:
                        if response.status != 200:
                            error_msg = "tigergraph delete_all_edges_by_source failed: url={}, {} {}".format(
                            delete_url, response.status, response.reason)
                            logging.error(error_msg)
                            response_text = await response.text()
                            logging.error(f"tigergraph delete_all_edges_by_source failed response content: {response_text}")
                            raise Exception(error_msg)
                        
                        # Read the response text
                        raw_text = await response.text()
                        # Optionally parse JSON response if needed
                        res = json.loads(raw_text)
                        if "error" in res:
                            if res["error"] is True:
                                error_msg = "tigergraph delete_all_edges_by_source failed: url={}, error={}".format(delete_url, res)
                                logging.warn(error_msg)
                                # raise Exception(error_msg)

                        logging.debug(f"Successfully deleted edges: {encoded_vid}/{edge_type}")

                except aiohttp.ClientError as e:
                    logging.error(f"Network error occurred: {e}")
                    raise