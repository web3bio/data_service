#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-10-06 17:23:57
LastEditors: Zella Zhong
LastEditTime: 2024-10-09 14:31:34
FilePath: /data_service/src/scalar/network.py
Description: 
'''
import strawberry
from enum import Enum

@strawberry.enum
class Network(Enum):
    ethereum = "ethereum"
    rsk = "rsk"
    vechain = "vechain"
    optimism = "optimism"
    cronos = "cronos"
    bnb_smart_chain = "bnb_smart_chain"
    gochain = "gochain"
    ethereum_classic = "ethereum_classic"
    tomochain = "tomochain"
    poa = "poa"
    gnosis = "gnosis"
    thundercore = "thundercore"
    polygon = "polygon"
    manta_pacific = "manta_pacific"
    energy_web = "energy_web"
    fantom_opera = "fantom_opera"
    boba = "boba"
    zksync = "zksync"
    theta = "theta"
    callisto = "callisto"
    metis = "metis"
    mantle = "mantle"
    base = "base"
    energi = "energi"
    arbitrum_one = "arbitrum_one"
    celo = "celo"
    avalanche_c_chain = "avalanche_c_chain"
    linea = "linea"
    scroll = "scroll"
    zora = "zora"

    # Non-EVM
    bitcoin = "bitcoin"
    litecoin = "litecoin"
    dogecoin = "dogecoin"
    reddcoin = "reddcoin"
    dash = "dash"
    peercoin = "peercoin"
    namecoin = "namecoin"
    viacoin = "viacoin"
    digibyte = "digibyte"
    monacoin = "monacoin"
    aib = "aib"
    syscoin = "syscoin"
    bitcoin_cash = "bitcoin_cash"
    bitcoinsv = "bitcoinsv"
    litecoincash = "litecoincash"
    verge = "verge"
    stratis = "stratis"
    ark = "ark"
    zencash = "zencash"
    zcash = "zcash"
    firo = "firo"
    ripple = "ripple"
    bitcoin_gold = "bitcoin_gold"
    ravencoin = "ravencoin"
    divi_project = "divi_project"
    neo = "neo"
    counos = "counos"
    counos_x = "counos_x"
    bitcoin_pos = "bitcoin_pos"
    large_coin = "large_coin"
    bitcoin_diamond = "bitcoin_diamond"
    tezos = "tezos"
    flux = "flux"
    waykichain = "waykichain"

    decred = "decred"
    monero = "monero"
    near_protocol = "near_protocol"
    solana = "solana"
    haven_protocol = "haven_protocol"
    hive = "hive"

    atom = "atom"
    iotex = "iotex"
    terra = "terra"
    iota = "iota"
    bnb = "bnb"
    harmony_one = "harmony_one"

    hedera_hbar = "hedera_hbar"
    v_systems = "v_systems"
    lisk = "lisk"
    steem = "steem"
    polkadot = "polkadot"

    cardano = "cardano"
    flow = "flow"

@strawberry.type
class Address:
    network: Network
    address: str


CoinTypeMap = {
    "eth": Network.ethereum,
    "rbtc": Network.rsk,
    "vet": Network.vechain,
    "op": Network.optimism,
    "cro": Network.cronos,
    "bsc": Network.bnb_smart_chain,
    "go": Network.gochain,
    "etc": Network.ethereum_classic,
    "tomo": Network.tomochain,
    "poa": Network.poa,
    "gno": Network.gnosis,
    "tt": Network.thundercore,
    "matic": Network.polygon,
    "manta": Network.manta_pacific,
    "ewt": Network.energy_web,
    "ftm": Network.fantom_opera,
    "boba": Network.boba,
    "zksync": Network.zksync,
    "theta": Network.theta,
    "clo": Network.callisto,
    "metis": Network.metis,
    "mantle": Network.mantle,
    "base": Network.base,
    "nrg": Network.energi,
    "arb1": Network.arbitrum_one,
    "celo": Network.celo,
    "avaxc": Network.avalanche_c_chain,
    "linea": Network.linea,
    "scr": Network.scroll,
    "zora": Network.zora,

    # Non-EVM
    "btc": Network.bitcoin,
    "ltc": Network.litecoin,
    "doge": Network.dogecoin,
    "rdd": Network.reddcoin,
    "dash": Network.dash,
    "ppc": Network.peercoin,
    "nmc": Network.namecoin,
    "via": Network.viacoin,
    "dgb": Network.digibyte,
    "mona": Network.monacoin,
    "aib": Network.aib,
    "vsys": Network.syscoin,
    "bch": Network.bitcoin_cash,
    "bsv": Network.bitcoinsv,
    "lcc": Network.litecoincash,
    "xvg": Network.verge,
    "strat": Network.stratis,
    "ark": Network.ark,
    "zen": Network.zencash,
    "zec": Network.zcash,
    "firo": Network.firo,
    "xrp": Network.ripple,
    "btg": Network.bitcoin_gold,
    "rvn": Network.ravencoin,
    "divi": Network.divi_project,
    "neo": Network.neo,
    "cca": Network.counos,
    "ccxx": Network.counos_x,
    "bps": Network.bitcoin_pos,
    "lrg": Network.large_coin,
    "bcd": Network.bitcoin_diamond,
    "xtz": Network.tezos,
    "flux": Network.flux,
    "wicc": Network.waykichain,

    "dcr": Network.decred,
    "xmr": Network.monero,
    "near": Network.near_protocol,
    "sol": Network.solana,
    "xhv": Network.haven_protocol,
    "hive": Network.hive,

    "atom": Network.atom,
    "iotx": Network.iotex,
    "luna": Network.terra,
    "iota": Network.iota,
    "bnb": Network.bnb,
    "one": Network.harmony_one,

    "hbar": Network.hedera_hbar,
    "vsys_custom": Network.v_systems,
    "lsk": Network.lisk,
    "steem": Network.steem,
    "dot": Network.polkadot,

    "ada": Network.cardano,
    "flow": Network.flow,
}