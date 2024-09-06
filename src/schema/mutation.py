#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-08-28 22:21:58
LastEditors: Zella Zhong
LastEditTime: 2024-08-28 22:29:45
FilePath: /cryptodata_apollographql/src/schema/mutation.py
Description: 
'''
import strawberry

from scalar import UpdatePostResponse
from resolver import update_post

@strawberry.type
class Mutation:
    @strawberry.mutation
    async def update_post(self, text: str, post_id: int) -> UpdatePostResponse:
        """ update post """
        update_resp = await update_post(text, post_id)
        return update_resp