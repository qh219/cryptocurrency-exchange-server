#!/usr/bin/python3

from algosdk import mnemonic
from algosdk import account
from web3 import Web3

"""
Generating key-pairs for the exchange on both the Ethereum and Algorand platforms
"""

#generate key-pairs for Ethereum
w3.eth.account.enable_unaudited_hdwallet_features()
acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()
#save Ethereum account information
acct = w3.eth.account.from_mnemonic(mnemonic_secret)
eth_pk = acct._address
eth_sk = acct._private_key


#generate accounts for Algorand
mnemonic_secret = "YOUR MNEMONIC HERE"
sk = mnemonic.to_private_key(mnemonic_secret)
pk = mnemonic.to_public_key(mnemonic_secret)


