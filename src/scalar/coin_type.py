#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-09 12:52:11
LastEditors: Zella Zhong
LastEditTime: 2024-10-09 12:58:51
FilePath: /data_service/src/scalar/coin_type.py
Description: 
'''
import strawberry
from enum import Enum

@strawberry.enum
class CoinType(Enum):
    eth = "eth"
    etcLegacy = "etcLegacy"
    rbtc = "rbtc"
    vet = "vet"
    op = "op"
    cro = "cro"
    bsc = "bsc"
    go = "go"
    etc = "etc"
    tomo = "tomo"
    poa = "poa"
    gno = "gno"
    tt = "tt"
    matic = "matic"
    manta = "manta"
    ewt = "ewt"
    ftm = "ftm"
    boba = "boba"
    zksync = "zksync"
    theta = "theta"
    clo = "clo"
    metis = "metis"
    mantle = "mantle"
    base = "base"
    nrg = "nrg"
    arb1 = "arb1"
    celo = "celo"
    avaxc = "avaxc"
    linea = "linea"
    scr = "scr"
    zora = "zora"
    btc = "btc"
    ltc = "ltc"
    doge = "doge"
    rdd = "rdd"
    dash = "dash"
    ppc = "ppc"
    nmc = "nmc"
    via = "via"
    dgb = "dgb"
    mona = "mona"
    aib = "aib"
    vsys = "vsys"
    bch = "bch"
    bsv = "bsv"
    lcc = "lcc"
    xvg = "xvg"
    strat = "strat"
    ark = "ark"
    zen = "zen"
    zec = "zec"
    firo = "firo"
    xrp = "xrp"
    btg = "btg"
    rvn = "rvn"
    divi = "divi"
    neo = "neo"
    cca = "cca"
    ccxx = "ccxx"
    bps = "bps"
    lrg = "lrg"
    bcd = "bcd"
    xtz = "xtz"
    flux = "flux"
    wicc = "wicc"
    dcr = "dcr"
    xmr = "xmr"
    near = "near"
    sol = "sol"
    xhv = "xhv"
    hive = "hive"
    atom = "atom"
    iotx = "iotx"
    luna = "luna"
    iota = "iota"
    bnb = "bnb"
    one = "one"
    hbar = "hbar"
    vsys_custom = "vsys_custom"
    lsk = "lsk"
    steem = "steem"
    dot = "dot"
    ada = "ada"
    flow = "flow"


@strawberry.type
class Record:
    coin_type: CoinType
    address: str
