#!/usr/bin/python3

from algosdk import mnemonic
from algosdk import account
from web3 import Web3
from send_tokens import connect_to_eth, connect_to_algo

"""
Generating key-pairs for the exchange on both the Ethereum and Algorand platforms
"""


def generate_eth_keys():

    # generate key-pairs for Ethereum
    w3 = connect_to_eth()
    w3.eth.account.enable_unaudited_hdwallet_features()
    acct, mnemonic_secret = w3.eth.account.create_with_mnemonic()  #*****************
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk = acct._address
    eth_sk = acct._private_key

    # save Ethereum account information

    #mnemonic_secret = "village token veteran"
    #eth_sk = mnemonic.to_private_key(mnemonic_secret)
    #eth_pk = mnemonic.to_public_key(mnemonic_secret)

    return eth_sk, eth_pk



def generate_algo_keys():

    #generate accounts for Algorand
    # generate an account and use mnemonics to store both public and private keys

    (private_key, sender_pk) = account.generate_account()  # generate_account() returns private key and address *****
    #***************  store str as mnemonic_secret
    #mnemonic_secret = mnemonic.from_private_key(private_key) #*************

    mnemonic_secret = "supreme whisper tumble erase section category denial divorce veteran syrup crack mean surround " \
                      "entire outside assault snake control moment half word govern cheese ability ordinary"
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    #print(algo_pk)
    return algo_sk, algo_pk


