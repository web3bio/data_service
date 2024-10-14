#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-28 19:38:25
LastEditors: Zella Zhong
LastEditTime: 2024-10-15 00:47:58
FilePath: /data_service/src/setting/__init__.py
Description: 
'''
import sys
import logging
import os
import toml


Settings = {
    "env": "development",
    "datapath": "./data",
}

PG_DSN = {
    "async_cryptodata": "",
    "sync_cryptodata": "",
}

TIGERGRAPH_SETTINGS = {
    "host": "",
    "inner_port": 0,
    "restpp": 0,
    "username": "",
    "password": "",
    "graph_data_root": "",
    "social_graph_name": "",
    "social_graph_secret": "",
    "social_graph_token": "",
}

REDIS_SETTINGS = {
    "host": "",
    "port": 0,
    "password": "",
    "db": 0,
}

AUTHENTICATE = {
    "secret": ""
}


def load_dsn(config_file):
    """
    @description: load pg dsn
    @params: config_file
    @return dsn_settings
    """
    try:
        config = toml.load(config_file)
        pg_dsn_settings = {
            "async_read": config["pg_dsn"]["async_read"],
            "async_write": config["pg_dsn"]["async_write"],
            "sync_read": config["pg_dsn"]["sync_read"],
            "sync_write": config["pg_dsn"]["sync_read"],
        }
        return pg_dsn_settings
    except Exception as ex:
        logging.exception(ex)

def load_settings(env="test"):
    """
    @description: load configurations from file
    """
    global Settings
    global PG_DSN
    global TIGERGRAPH_SETTINGS
    global REDIS_SETTINGS
    global AUTHENTICATE
    config_file = "/app/config/production.toml"
    if env is not None:
        if env not in ["development", "test", "production"]:
            raise ValueError("Unknown environment")
        config_file = os.getenv("CONFIG_FILE")

    config = toml.load(config_file)
    Settings["env"] = env
    Settings["datapath"] = os.path.join(config["server"]["work_path"], "data")
    PG_DSN = load_dsn(config_file)
    TIGERGRAPH_SETTINGS = {
        "host": config["tdb"]["host"],
        "inner_port": config["tdb"]["inner_port"],
        "restpp": config["tdb"]["restpp"],
        "username": config["tdb"]["username"],
        "password": config["tdb"]["password"],
        "graph_data_root": config["tdb"]["graph_data_root"],
        "social_graph_name": config["tdb"]["social_graph_name"],
        "social_graph_secret": config["tdb"]["social_graph_secret"],
        "social_graph_token": config["tdb"]["social_graph_token"],
    }
    REDIS_SETTINGS = {
        "host": config["redis"]["host"],
        "port": config["redis"]["port"],
        "password": config["redis"]["password"],
        "db": config["redis"]["db"],
    }
    AUTHENTICATE = {
        "secret": config["authenticate"]["secret"],
    }
    return config


# Preload configuration
load_settings(env=os.getenv("ENVIRONMENT"))
