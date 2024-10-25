#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Zella Zhong
Date: 2024-09-12 19:13:33
LastEditors: Zella Zhong
LastEditTime: 2024-10-25 15:22:33
FilePath: /data_service/src/utils/address.py
Description: 
'''
import base58
from eth_utils import to_checksum_address, is_address


def is_ethereum_address(address):
    if len(address) != 42:
        return False

    try:
        return is_address(address)
    except:
        return False


def is_base58_solana_address(address):
    # Check for exact length of Solana address (44 characters when Base58 encoded)
    if len(address) != 44:
        return False
    
    try:
        # Try to decode the address from Base58
        decoded = base58.b58decode(address)
        # Ensure the decoded length is 32 bytes (for Solana public keys)
        return len(decoded) == 32
    except ValueError:
        # Decoding will fail if `address` is not valid Base58
        return False


def hexstr_to_solana_address(hex_data):
    # Strip the "0x" prefix if present
    if hex_data.startswith("0x"):
        hex_data = hex_data[2:]

    # Convert the hex string to bytes
    raw_bytes = bytes.fromhex(hex_data)

    # Base58 encode the raw bytes to get the Solana address
    solana_address = base58.b58encode(raw_bytes).decode('utf-8')

    return solana_address


def bytea_to_eth_checksum_address(bytea_value):
    ''' Function to convert BYTEA (byte string) to Ethereum address'''
    # Convert bytea_value (byte string) to hexadecimal, then to checksum address
    return to_checksum_address("0x" + bytea_value.hex())

def hexstr_to_eth_checksum_address(hex_data):
    ''' Function to convert hex_str to Ethereum address'''
    if hex_data.startswith("0x"):
        hex_data = hex_data[2:]
    return to_checksum_address("0x" + hex_data)

def bytea_to_hex_address(bytea_value):
    '''# Function to convert BYTEA to lowercase Ethereum address'''
    return "0x" + bytea_value.hex()


if __name__ == "__main__":
    address = "0x934b510d4c9103e6a87aef13b816fb080286d649"
    print("is_ethereum_address:", is_ethereum_address(address))

    address = "5v6vXweNfYHHxKB3Nj6MjsK6zAaZp3Xo1LxDwU5vnPnm"
    print("is_base58_solana_address:", is_base58_solana_address(address))