#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-28 19:38:25
LastEditors: Zella Zhong
LastEditTime: 2024-08-29 00:13:39
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

def load_dsn(config_file):
    """
    @description: load pg dsn
    @params: config_file
    @return dsn_settings
    """
    try:
        config = toml.load(config_file)
        pg_dsn_settings = {
            "async_cryptodata": config["pg_dsn"]["async_cryptodata"],
            "sync_cryptodata": config["pg_dsn"]["sync_cryptodata"],
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

    config_file = "/app/config/production.toml"
    if env is not None:
        if env not in ["development", "test", "production"]:
            raise ValueError("Unknown environment")
        config_file = os.getenv("CONFIG_FILE")

    config = toml.load(config_file)
    Settings["env"] = env
    Settings["datapath"] = os.path.join(config["server"]["work_path"], "data")
    PG_DSN = load_dsn(config_file)
    return config


# Preload configuration
load_settings(env=os.getenv("ENVIRONMENT"))
