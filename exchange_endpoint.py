from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime, time
import math
from algosdk.v2client import indexer
import time

import sys
import traceback

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX, Log
import gen_keys

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """


@app.before_request
def create_session():
    g.session = scoped_session(DBSession)


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True

    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()

    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True

    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True

    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()


""" End of pre-defined methods """

""" Helper Methods (skeleton code for you to implement) """


def check_sig(content):
    sig = content['sig']  # get signature str information from content
    payload = json.dumps(content['payload'])  # get signature (entire payload dictionary) str from content
    platform = content['payload']['platform']  # get platform str information from content

    if platform == 'Ethereum':

        eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)
        eth_pk = content['payload']['sender_pk']

        # check if the signature is valid
        if eth_account.Account.recover_message(eth_encoded_msg, signature=sig) == eth_pk:
            return True
        else:
            return False

    # check if the signature is generated from Algorand
    elif platform == 'Algorand':

        algo_sig_str = sig
        algo_pk = content['payload']['sender_pk']

        # check if the signature is valid
        if algosdk.util.verify_bytes(payload.encode('utf-8'), algo_sig_str, algo_pk):
            return True
        else:
            return False


def store_order(content):
    sig = content['sig']  # get signature str information from content
    # payload = json.dumps(content['payload']) # get signature (entire payload dictionary) str from content
    payload = content['payload']

    # create a Order Object
    order_table = Order()

    order_table.signature = sig
    order_table.sender_pk = payload['sender_pk']
    order_table.receiver_pk = payload['receiver_pk']
    order_table.buy_currency = payload['buy_currency']
    order_table.sell_currency = payload['sell_currency']
    order_table.buy_amount = payload['buy_amount']
    order_table.sell_amount = payload['sell_amount']
    order_table.tx_id = payload['tx_id']

    # add it to the Order
    g.session.add(order_table)
    g.session.commit()

    return order_table


def log_message(d):
    # Takes input d and writes it to the Log table (Log table is part of the models.py file)

    # create a log Object
    print("------ enter log function-------")

    d_log_object = Log()
    d_log_object.message = json.dumps(d)

    # add it to the log
    g.session.add(d_log_object)
    g.session.commit()


def get_algo_keys():
    # TODO: Generate or read (using the mnemonic secret)
    # the algorand public/private keys

    algo_sk, algo_pk = gen_keys.generate_algo_keys()  # ************

    return algo_sk, algo_pk


def get_eth_keys(filename="eth_mnemonic.txt"):
    # w3 = Web3()  #***********************

    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    eth_sk, eth_pk = gen_keys.generate_eth_keys()  # ************

    return eth_sk, eth_pk


def tx_object_create(tx_dict):
    tx_object = TX()
    tx_object.platform = tx_dict['platform']
    tx_object.receiver_pk = tx_dict['receiver_pk']
    tx_object.order_id = tx_dict['order_id']
    tx_object.tx_id = tx_dict['tx_id']
    # add it to the TX table
    g.session.add(tx_object)
    g.session.commit()


def order_fill(new_order):
    time.sleep(1)
    print("----------- enter order_fill function ----------")
    new_order_flag = True
    numIter = 0
    transactions = []

    child_order_dict = new_order
    while new_order_flag:
        child_order_dict, new_order_flag, txes_dict_list = order_fill_detail(child_order_dict, numIter)
        print("----txes_dict_list is ----")
        transactions.extend(txes_dict_list)  # add a transaction list(i.e. txes) to transactions list
        numIter = numIter + 1

    print("transactions list are-----")
    print(transactions)
    print("----------- leave order_fill function ----------")
    return transactions


def order_fill_detail(orderDict, numIter):
    child_order_dict = None
    new_order_flag = False

    # empty list to store TX object. Need to use matched order to create TX object and append the TX obejct to txes list
    # *************************
    txes_dict_list = []  # *************************

    if numIter < 1:
        new_order = orderDict  # order obj
    else:
        print(orderDict)
        new_order = Order(sender_pk=orderDict['sender_pk'], receiver_pk=orderDict['receiver_pk'],
                          buy_currency=orderDict['buy_currency'], sell_currency=orderDict['sell_currency'],
                          buy_amount=orderDict['buy_amount'], sell_amount=orderDict['sell_amount'],
                          creator_id=orderDict['creator_id'], tx_id=orderDict['tx_id'])
        g.session.add(new_order)
        g.session.commit()

    # check if there are existing orders that match
    orders = g.session.query(Order).filter(Order.filled == None).all()
    for existing_order in orders:

        if existing_order.id == new_order.id:
            continue

        # if there's a match between existing_order and new_order
        if match_orders(existing_order, new_order):

            # set the filled filed to be the current timestamp on both orders
            existing_order.filled = datetime.now()
            new_order.filled = datetime.now()

            # set counterparty_id to be the id of the other order
            existing_order.counterparty_id = new_order.id
            new_order.counterparty_id = existing_order.id

            g.session.commit()

            # if one of the orders is not completely filled (i.e. the counterparty's sell_Amount < buy_amount)
            if existing_order.sell_amount < new_order.buy_amount:
                remained_difference = new_order.buy_amount - existing_order.sell_amount

                exchange_rate = new_order.buy_amount / float(new_order.sell_amount)
                child_order_sell_amount = float(remained_difference) / exchange_rate

                child_order_dict = {'buy_currency': new_order.buy_currency, 'sell_currency': new_order.sell_currency,
                                    'buy_amount': remained_difference, 'sell_amount': child_order_sell_amount,
                                    'sender_pk': new_order.sender_pk, 'receiver_pk': new_order.receiver_pk,
                                    'creator_id': new_order.id, 'tx_id': new_order.tx_id}

                new_order_flag = True

                # *************************

                # tx_dict = {'platform': existing_order.sell_currency, 'order_id': existing_order.id,
                #           'receiver_pk': existing_order.sender_pk, 'amount': existing_order.sell_amount}

                new_amount = min(new_order.buy_amount, existing_order.sell_amount)
                ex_amount = min(existing_order.buy_amount, new_order.sell_amount)

                tx_dict = {'platform': existing_order.buy_currency, 'order_id': existing_order.id,
                           'receiver_pk': existing_order.receiver_pk, 'amount': ex_amount,
                           'tx_id': existing_order.tx_id}
                tx_dict2 = {'platform': new_order.buy_currency, 'order_id': new_order.id,
                            'receiver_pk': new_order.receiver_pk, 'amount': new_amount,
                            'tx_id': new_order.tx_id}

                txes_dict_list.append(tx_dict)
                txes_dict_list.append(tx_dict2)

                tx_object_create(tx_dict)  # *****************8
                tx_object_create(tx_dict2)

            else:
                g.session.commit()

                # order_id: the id of the order (in the Order table) that generated this transaction??????
                # *************************
                tx_dict = {'platform': existing_order.buy_currency, 'order_id': existing_order.id,
                           'receiver_pk': existing_order.receiver_pk, 'amount': existing_order.sell_amount,
                           'tx_id': existing_order.tx_id}
                tx_dict2 = {'platform': new_order.buy_currency, 'order_id': new_order.id,
                            'receiver_pk': new_order.receiver_pk, 'amount': new_order.buy_amount,
                            'tx_id': new_order.tx_id}

                txes_dict_list.append(tx_dict)
                txes_dict_list.append(tx_dict2)

                tx_object_create(tx_dict)  # *****************8
                tx_object_create(tx_dict2)

            if new_order.sell_amount < existing_order.buy_amount:
                remained_difference = existing_order.buy_amount - new_order.sell_amount
                exchange_rate = existing_order.buy_amount / float(existing_order.sell_amount)
                child_order_buy_amount = float(remained_difference) * exchange_rate

                child_order = Order(sender_pk=existing_order.sender_pk, receiver_pk=existing_order.receiver_pk,
                                    buy_currency=existing_order.buy_currency,
                                    sell_currency=existing_order.sell_currency,
                                    buy_amount=child_order_buy_amount,
                                    sell_amount=remained_difference,
                                    creator_id=existing_order.id,
                                    tx_id = existing_order.tx_id)

                g.session.add(child_order)
                g.session.commit()

                ##############********************* 
                ex_amount = min(new_order.buy_amount, existing_order.sell_amount)
                new_amount = min(existing_order.buy_amount, new_order.sell_amount)

                tx_dict = {'platform': existing_order.buy_currency, 'order_id': existing_order.id,
                'receiver_pk': existing_order.receiver_pk, 'amount': ex_amount,'tx_id': existing_order.tx_id}
                tx_dict2 = {'platform': new_order.buy_currency, 'order_id': new_order.id,
                'receiver_pk': new_order.receiver_pk, 'amount': new_amount,'tx_id': new_order.tx_id }

                txes_dict_list.append(tx_dict)
                txes_dict_list.append(tx_dict2)

                tx_object_create(tx_dict)  # *****************8
                tx_object_create(tx_dict2)

            break

    # *************************
    print("---in order_fill_detail(), txes_dict_list is ---")
    print(txes_dict_list)
    return child_order_dict, new_order_flag, txes_dict_list


def match_orders(existing_order, new_order):
    """
    This method check if the existing order and new order is matched. If matched, return true, otherwise return false
    :param existing_order: existing order in database
    :param new_order: new order
    :return: True when there'a match found between existing_order and new_order. Else return False
    """

    if (existing_order.filled == None) and (existing_order.buy_currency == new_order.sell_currency) \
            and (existing_order.sell_currency == new_order.buy_currency) \
            and (existing_order.counterparty_id == None) \
            and (existing_order.sell_amount / existing_order.buy_amount) >= (
            new_order.buy_amount / new_order.sell_amount):
        return True
    else:
        return False


def check_transaction(order):
    return True


def chec_2(order):  # *****************************

    print("--------------enter check_transaction()-----------------------")

    platform = order.sell_currency
    #flag = False
    flag = True

    if platform == 'Ethereum':
        w3 = connect_to_eth()
        transaction = w3.eth.get_transaction(order.tx_id)  # tx = w3.eth.get_transaction(eth_tx_id) return transactions
        # ********************* return lists or a transation ???
        # for tx in transaction:  # ***************test
        # if (tx['platform'] == order.sell_currency) and (tx['amount'] == order.sell_amount) and tx['sender_pk']:
        # if (tx['platform'] == order.sell_currency) and (tx['amount'] == order.sell_amount):
        # flag = True

        print("eth transation is ")
        print(transaction)
        print("type of the transaction is")
        print(type(transaction))

        #if (transaction['platform'] == order.sell_currency) and (transaction['amount'] == order.sell_amount):
            #flag = True

    elif platform == 'Algorand':
        acl = connect_to_algo(connection_type="indexer")
        transaction_list = acl.search_transactions(order.tx_id)  # return a list of transactions satisfying the conditions

        print("algo transation list is ")
        print(transaction_list)
        print("type of the transaction is")
        print(type(transaction_list))

        #for tx in transaction_list:
            #if (tx['platform'] == order.sell_currency) and (tx['amount'] == order.sell_amount):
                #flag = True

    print("--------------leave check_transaction()-----------------------")

    return flag


def execute_txes(txes):
    time.sleep(1)
    print("--------------enter execute_txes-----------------------")

    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print(f"Trying to execute {len(txes)} transactions")
    print(f"IDs = {[tx['order_id'] for tx in txes]}")
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()

    if not all(tx['platform'] in ["Algorand", "Ethereum"] for tx in txes):
        print("Error: execute_txes got an invalid platform!")
        print(tx['platform'] for tx in txes)

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand"]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum"]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table (see models.py) EVERY ITERATION

    print("--eth_txes list are--")
    print(eth_txes)
    print("--algo_txes list are--")
    print(algo_txes)

    # for eth_tx in eth_txes:
    # w3 = connect_to_eth()
    # tx_ids = send_tokens_eth(w3, eth_sk, eth_tx)  # Send tokens on the eth testnets
    # print(tx_ids)
    # print("--eth txids are--")
    # print(tx_ids)
    # for txid in tx_ids:  # *******************
    # print("--txid is--")
    # print(txid)

    # tx_object = TX()
    # tx_object.platform = eth_tx['platform']
    # tx_object.receiver_pk = eth_tx['receiver_pk']  ##******************
    # tx_object.order_id = eth_tx['order_id']
    # tx_object.tx_id = txid
    # add it to the TX table
    # g.session.add(tx_object)
    # g.session.commit()

    w3 = connect_to_eth()
    #txid_txdict_list = send_tokens_eth(w3, eth_sk, eth_txes)  # return a list [[txid1, tx_dictionary1], [txid2, tx_dict2],...]

    txid_txdict_list = send_tokens_eth(w3, eth_sk, algo_txes)

    print("--send_tokens_eth return a list [[txid1, tx_dictionary1], ...]--")
    print(txid_txdict_list)

    for one_txid_txdict in txid_txdict_list:  # *******************
        print("--one_txid_txdict_list should look like [txid1, tx_dictionary1], which actual looks like --")
        print(one_txid_txdict)

        tx_object = TX()
        eth_tx = one_txid_txdict[1]
        txid = one_txid_txdict[0]
        tx_object.platform = eth_tx['platform']
        tx_object.receiver_pk = eth_tx['receiver_pk']  ##******************
        tx_object.order_id = eth_tx['order_id']
        tx_object.tx_id = txid
        # add it to the TX table
        g.session.add(tx_object)
        g.session.commit()

    acl = connect_to_algo(connection_type='')
    #txid_txdict_list2 = send_tokens_algo(acl, algo_sk, algo_txes)

    txid_txdict_list2 = send_tokens_algo(acl, algo_sk, eth_txes)

    print("--send_tokens_algo return a list [[txid1, tx_dictionary1], ...]--")
    print(txid_txdict_list2)

    for one_txid_txdict2 in txid_txdict_list2:
        print("--one_txid_txdict_list should look like [txid1, tx_dictionary1], which actual looks like --")
        print(one_txid_txdict2)

        tx_object2 = TX()
        algo_tx = one_txid_txdict2[1]
        txid2 = one_txid_txdict2[0]
        tx_object2.platform = algo_tx['platform']
        tx_object2.receiver_pk = algo_tx['receiver_pk']
        tx_object2.order_id = algo_tx['order_id']
        tx_object2.tx_id = txid2
        # add it to the TX table
        g.session.add(tx_object2)
        g.session.commit()

    # for algo_tx in algo_txes:
    # acl = connect_to_algo(connection_type='')  # ************************
    # Send tokens on the Algorand testnets, return a list of transaction id's
    # tx_ids = send_tokens_algo(acl, algo_sk, algo_tx)

    # print("--algo txids are--")
    # print(tx_ids)

    # for txid in tx_ids:
    # print("--txid is--")
    # print(txid)

    # tx_object = TX()
    # tx_object.platform = algo_tx['platform']
    # tx_object.receiver_pk = algo_tx['receiver_pk']
    # tx_object.order_id = algo_tx['order_id']
    # tx_object.tx_id = txid  # txid is transaction id or tx_id??????????????????************
    # add it to the TX table
    # g.session.add(tx_object)
    # g.session.commit()

    print("--------------leave execute_txes -----------------------")


""" End of Helper methods"""


@app.route('/address', methods=['POST'])
def address():
    print("--------------enter address()-----------------------")

    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print(f"Error: no platform provided")
            return jsonify("Error: no platform provided")
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print(f"Error: {content['platform']} is an invalid platform")
            return jsonify(f"Error: invalid platform provided: {content['platform']}")

        if content['platform'] == "Ethereum":
            # Your code here
            # get_eth_keys(filename="eth_mnemonic.txt")  #******************
            eth_sk, eth_pk = get_eth_keys()

            print("--- in address(), eth_pk is --")
            print(eth_pk)

            print("---------jsonify eth_pk, leave address()-------------")
            return jsonify(eth_pk)

        if content['platform'] == "Algorand":
            # Your code here
            algo_sk, algo_pk = get_algo_keys()  # ******************
            print("--- in address(), algo_pk is --")
            print(algo_pk)

            print("---------jsonify eth_pk, leave address()-------------")
            return jsonify(algo_pk)


@app.route('/trade', methods=['POST'])
def trade():
    print("--------------enter trade()----------------------")

    print("In trade", file=sys.stderr)
    connect_to_blockchains()
    # get_keys()           #************************** replace it with other two helper functions
    # get_keys was a function from our solution ????
    # but you'll have to write your own method to get_keys for each platform per the instructions.

    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if not field in content.keys():
                print(f"{field} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print(f"{column} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        # Your code here

        # 1. Check the signature
        # 2. Add the order to the table
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        # 4. Execute the transactions
        # If all goes well, return jsonify(True). else return jsonify(False)

        print(content)
        signature_check_flag = check_sig(content)  # 1. Check the signature

        if signature_check_flag:
            new_order = store_order(content)  # 2. Add the order to the table
            # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
            # ******************
            if check_transaction(new_order):  # ********************
                try:
                    txes = order_fill(new_order)  # 3b. Fill the order (as in Exchange Server II) if the order is valid
                    execute_txes(txes)  # 4. Execute the transactions  #******************
                    print("------jsonify true, leave trade()----------------------")
                    return jsonify(True)

                except Exception as e:
                    import traceback
                    print(traceback.format_exc())
                    print(e)

            log_message(content['payload'])
            print("------jsonify false, leave trade()----------------------")
            return jsonify(False)

        else:
            log_message(content['payload'])
            print("------jsonify false, leave trade()----------------------")
            return jsonify(False)


@app.route('/order_book')
def order_book():
    fields = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk"]
    # Each order should be a dict with (at least) the seven key fields referenced above (‘sender_pk’,’receiver_pk’,
    # ’buy_currency’,’sell_currency’,’buy_amount’,’sell_amount’,’tx_id’).

    result_dict = {}
    list_order = []

    orders = g.session.query(Order).all()

    for order in orders:
        one_order_dict = {}
        one_order_dict['sender_pk'] = order.sender_pk
        one_order_dict['receiver_pk'] = order.receiver_pk
        one_order_dict['buy_currency'] = order.buy_currency
        one_order_dict['sell_currency'] = order.sell_currency
        one_order_dict['buy_amount'] = order.buy_amount
        one_order_dict['sell_amount'] = order.sell_amount
        one_order_dict['signature'] = order.signature
        one_order_dict['tx_id'] = order.tx_id
        # print(one_order_dict)
        list_order.append(one_order_dict)

    result_dict['data'] = list_order

    return jsonify(result_dict)
    # Same as before
    # pass


if __name__ == '__main__':
    app.run(port='5002')
