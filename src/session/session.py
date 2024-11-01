#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-28 19:11:06
LastEditors: Zella Zhong
LastEditTime: 2024-11-01 03:36:36
FilePath: /data_service/src/session/session.py
Description: 
'''
import asyncpg

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

import setting

engine = create_async_engine(setting.PG_DSN["async_read"])

async_session = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        async with session.begin():
            try:
                yield session
            finally:
                await session.close()

@asynccontextmanager
async def get_asyncpg_session():
    conn = await asyncpg.connect(setting.PG_DSN["sync_write"])
    try:
        yield conn
    finally:
        await conn.close()