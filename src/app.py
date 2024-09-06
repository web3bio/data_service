#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-28 19:02:56
LastEditors: Zella Zhong
LastEditTime: 2024-08-29 23:20:43
FilePath: /cryptodata_apollographql/src/app.py
Description: 
'''
import os
import uvicorn
import logging
import strawberry

from dotenv import load_dotenv
load_dotenv()

from datetime import datetime, timezone
from fastapi import FastAPI
from strawberry.fastapi import GraphQLRouter
from strawberry.schema.config import StrawberryConfig
from strawberry.extensions import MaskErrors

import setting
import setting.filelogger as logger
from schema import Query, Mutation
from scalar.error import should_mask_error
from scalar.common import BigInt, EpochDateTime

schema = strawberry.Schema(
    query=Query,
    config=StrawberryConfig(
        auto_camel_case=True
    ),
    scalar_overrides={datetime: EpochDateTime, int: BigInt},
    extensions=[
        MaskErrors(should_mask_error=should_mask_error),
    ],
    
)


def create_app():
    app = FastAPI()
    graphql_app = GraphQLRouter(schema)
    app.include_router(graphql_app, prefix="/graphql")
    return app


def set_log_config():
    uvicorn_log_config = uvicorn.config.LOGGING_CONFIG
    format = "[%(asctime)s - %(levelname)s %(process)s %(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    uvicorn_log_config["formatters"]["access"]["fmt"] = format
    uvicorn_log_config["formatters"]["default"]["fmt"] = format
    return uvicorn_log_config

application = create_app()

if __name__ == "__main__":
    config = setting.load_settings(env=os.getenv("ENVIRONMENT"))
    if not os.path.exists(config["server"]["log_path"]):
        os.makedirs(config["server"]["log_path"])

    worker_number = config["server"]["process_count"]
    host = config["server"]["ip"]
    port = config["server"]["port"]
    logger.InitLogger(config)
    logging.info(f"Starting server http://{host}:{port}/graphql {worker_number} process ...")
    if setting.Settings["env"] == "development":
        # Debug mode reload file changed
        uvicorn.run("app:application", host=host, port=port, reload=True, log_level=logging.INFO)
    else:
        uvicorn.run("app:application", host=host, port=port, workers=worker_number, log_level=logging.ERROR)
