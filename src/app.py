#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-28 19:02:56
LastEditors: Zella Zhong
LastEditTime: 2024-10-25 19:41:58
FilePath: /data_service/src/app.py
Description: main entry point
'''
import re
import os
import time
import uvicorn
import logging
import strawberry

from dotenv import load_dotenv
load_dotenv()

from datetime import datetime, timezone
from fastapi import FastAPI, Request, HTTPException
from starlette.responses import JSONResponse
from starlette.responses import HTMLResponse
from strawberry.fastapi import GraphQLRouter
from strawberry.schema.config import StrawberryConfig
from strawberry.extensions import MaskErrors


from cache.redis import RedisClient

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

# def create_app():
#     app = FastAPI()
#     graphql_app = MyGraphQLRouter(schema)
#     app.include_router(graphql_app, prefix="/graphql")
#     return app


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

@application.middleware("http")
async def limit_rate(request: Request, call_next):
    try:
        # Access the global Redis client instance
        redis_client = await RedisClient.get_instance()

        # Check the Authorization header
        token = request.headers.get("Authorization")
        logging.debug("app token %s", token)

        # Check the User-Agent header
        user_agent = request.headers.get("User-Agent", "")
        is_browser = bool(re.search(r"Mozilla|Chrome|Safari|Firefox|Opera", user_agent))

        if token:  # If token is present, allow requests without limits
            response = await call_next(request)
            return response

        # If token is missing, apply rate limiting
        client_ip = request.client.host
        requests_per_minute = 20
        requests_per_day = 5000

        # Relaxed rate limits for browser requests
        if is_browser:
            requests_per_minute = 40  # Allow 40 requests per minute
            requests_per_day = 10000  # Allow 10,000 requests per day

        logging.debug("client_ip %s", client_ip)

        # Rate limit keys
        rate_limit_key_minute = f"rate_limit:min:{client_ip}"
        rate_limit_key_day = f"rate_limit:day:{client_ip}"

        # Check the minute rate limit
        minute_count = await redis_client.get(rate_limit_key_minute)
        if minute_count and int(minute_count) >= requests_per_minute:
            logging.error(f"Rate limit exceeded for {client_ip}: {minute_count} requests in one minute")
            raise HTTPException(status_code=429, detail="Too Many Requests: 40 accesses per minute limit exceeded")

        # Increment minute counter and set expiration to 60 seconds
        await redis_client.incr(rate_limit_key_minute)
        await redis_client.expire(rate_limit_key_minute, 60)  # Expires in 60 seconds

        # Check the daily rate limit
        day_count = await redis_client.get(rate_limit_key_day)
        if day_count and int(day_count) >= requests_per_day:
            raise HTTPException(status_code=429, detail="Too Many Requests: 10,000 accesses per day limit exceeded")

        # Increment daily counter and set expiration to 24 hours
        await redis_client.incr(rate_limit_key_day)
        await redis_client.expire(rate_limit_key_day, 86400)  # Expires in 24 hours

        # Continue processing the request
        response = await call_next(request)
        return response

    except HTTPException as http_exc:
        # Handle HTTPException and return proper response
        return JSONResponse(
            status_code=http_exc.status_code,
            content={"code": http_exc.status_code, "msg": http_exc.detail}
        )

    except Exception as exc:
        logging.error(f"Unexpected error: {exc}")
        # Handle general exceptions with a 500 response
        return JSONResponse(
            status_code=500,
            content={"code": 500, "msg": "Internal Server Error"}
        )


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
