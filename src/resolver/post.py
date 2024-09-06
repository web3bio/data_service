#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-28 21:29:45
LastEditors: Zella Zhong
LastEditTime: 2024-08-29 00:37:39
FilePath: /cryptodata_apollographql/src/resolver/post.py
Description: 
'''
import logging
from datetime import datetime
from sqlalchemy import select, update
from sqlalchemy.orm import load_only

from session import get_session
from model import Post
from utils import get_only_selected_fields, check_valid_data
from scalar import PostNotFound


async def list_posts(info):
    """ Get all posts """
    selected_fields = get_only_selected_fields(Post, info)
    async with get_session() as s:
        sql = select(Post).options(load_only(*selected_fields)).order_by(Post.id)
        db_posts = (await s.execute(sql)).scalars().unique().all()

    posts = []
    for post in db_posts:
        posts_dict = check_valid_data(post, Post)
        posts.append(Post(**posts_dict))

    return posts


async def get_post(info, post_id):
    """ Get specific post by id """
    selected_fields = get_only_selected_fields(Post, info)
    async with get_session() as s:
        sql = select(Post).options(load_only(*selected_fields)) \
        .filter(Post.id == post_id).order_by(Post.id)
        db_post = (await s.execute(sql)).scalars().unique().one()

    post_dict = check_valid_data(db_post, Post)
    return Post(**post_dict)

async def update_post(text, post_id):
    """ update post """
    async with get_session() as s:
        sql = select(Post).where(Post.id == post_id)
        existing_db_post = (await s.execute(sql)).first()
        if existing_db_post is None:
            return PostNotFound()

        query = update(Post).where(Post.id == post_id).values(text=text)
        await s.execute(query)

        sql = select(Post).where(Post.id == post_id)
        db_post = (await s.execute(sql)).scalars().unique().one()
        await s.commit()

    post_dict = db_post.as_dict()
    return Post(**post_dict)
