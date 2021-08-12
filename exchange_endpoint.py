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
from datetime import datetime
import math
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

    algo_sk, algo_pk = gen_keys.generate_algo_keys()  #************

    return algo_sk, algo_pk


def get_eth_keys(filename="eth_mnemonic.txt"):
    #w3 = Web3()  #***********************

    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    eth_sk, eth_pk = gen_keys.generate_eth_keys()  #************

    return eth_sk, eth_pk


def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!

    pass


def order_fill(new_order):
    new_order_flag = True
    numIter = 0
    transactions = []

    child_order_dict = new_order
    while new_order_flag:
        child_order_dict, new_order_flag, txes_dict_list = order_fill_detail(child_order_dict, numIter)
        transactions.extend(txes_dict_list)  # add a transaction list(i.e. txes) to transactions list
        numIter = numIter + 1

    return transactions

def order_fill_detail(orderDict, numIter):
    child_order_dict = None
    new_order_flag = False

    # empty list to store TX object. Need to use matched order to create TX object and append the TX obejct to txes list
    # *************************
    txes_dict_list = [] # *************************

    if numIter < 1:
        new_order = orderDict  # order obj
    else:
        new_order = Order(sender_pk=orderDict['sender_pk'], receiver_pk=orderDict['receiver_pk'],
                          buy_currency=orderDict['buy_currency'], sell_currency=orderDict['sell_currency'],
                          buy_amount=orderDict['buy_amount'], sell_amount=orderDict['sell_amount'],
                          creator_id=orderDict['creator_id'])
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
                                    'creator_id': new_order.id}

                new_order_flag = True

                # *************************


                tx_dict = {'platform': existing_order.sell_currency, 'order_id': existing_order.id,
                           'receiver_pk': existing_order.sender_pk, 'amount': existing_order.sell_amount}
                txes_dict_list.append(tx_dict)


            else:
                g.session.commit()

                # order_id: the id of the order (in the Order table) that generated this transaction??????
                # *************************
                tx_dict = {'platform': existing_order.sell_currency, 'order_id': existing_order.id,
                           'receiver_pk': existing_order.sender_pk, 'amount': existing_order.sell_amount}
                txes_dict_list.append(dict)

            if new_order.sell_amount < existing_order.buy_amount:
                remained_difference = existing_order.buy_amount - new_order.sell_amount
                exchange_rate = existing_order.buy_amount / float(existing_order.sell_amount)
                child_order_buy_amount = float(remained_difference) * exchange_rate

                child_order = Order(sender_pk=existing_order.sender_pk, receiver_pk=existing_order.receiver_pk,
                                    buy_currency=existing_order.buy_currency,
                                    sell_currency=existing_order.sell_currency,
                                    buy_amount=child_order_buy_amount,
                                    sell_amount=remained_difference,
                                    creator_id=existing_order.id)

                g.session.add(child_order)
                g.session.commit()

                ##############*********************
                tx_dict = {'platform': new_order.sell_currency, 'order_id': new_order.id,
                           'receiver_pk': new_order.sender_pk, 'amount': new_order.sell_amount}
                txes_dict_list.append(tx_dict)

            break

    # *************************
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


def check_transaction(order):  #*****************************
    """When a user submits an order to the endpoint “/trade” the submission data should have a “tx_id” field.
    For valid orders, this will correspond to a transaction ID on the blockchain specified by “sell_currency.”
    In order to see if the order is valid, the exchange server must check that the specified transaction actually
    transferred “sell_amount” to the exchange’s address.
    the “/trade” endpoint should take an additional field “tx_id” which specifies the transaction ID (sometimes called the transaction hash) of the transaction that deposited tokens to the exchange. In particular, before filling an order, you must check
        1. The transaction specified by tx_id is a valid transaction on the platform specified by ‘sell_currency’
        2. The amount of the transaction is ‘sell_amount’
        3. The sender of the transaction is ‘sender_pk’   ****************************???????
        4. The receiver of the transaction is the exchange server (i.e., the key specified by the ‘/address’ endpoint) *****
    """

    platform = order.sell_currency
    flag = False

    if platform == 'Ethereum':
        w3 = connect_to_eth()
        tx = w3.eth.get_transaction(order.tx_id)    #tx = w3.eth.get_transaction(eth_tx_id) return transactions
        #********************* return lists or a transation ???
        if (tx['platform']== order.sell_currency ) and (tx['amount'] == order.sell_amount):
            flag = True

    elif platform == 'Algorand':
        acl = connect_to_algo(connection_type="indexer")
        transaction_list = acl.search_transactions(order.tx_id)  #return a list of transactions satisfying the conditions
        for tx in transaction_list:
            if (tx['platform'] == order.sell_currency) and (tx['amount'] == order.sell_amount):
                flag = True

    return flag


def execute_txes(txes):
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

    for eth_tx in eth_txes:
        w3 = connect_to_eth()
        tx_ids = send_tokens_eth(w3, eth_sk, eth_tx)  # Send tokens on the eth testnets

        for txid in tx_ids: #*******************
            tx_object = TX()
            tx_object.platform = eth_tx['platform']
            tx_object.receiver_pk = eth_tx['receiver_pk']  ##******************
            tx_object.order_id = eth_tx['order_id']
            tx_object.tx_id = txid  #txid is transaction id or tx_id??????????????????************
            # add it to the TX table
            g.session.add(tx_object)
            g.session.commit()


    for algo_tx in algo_txes:
        acl = connect_to_algo(connection_type='') # ************************
        # Send tokens on the Algorand testnets, return a list of transaction id's
        tx_ids = send_tokens_algo( acl, algo_sk, algo_tx)

        for txid in tx_ids:
            tx_object = TX()
            tx_object.platform = algo_tx['platform']
            tx_object.receiver_pk = algo_tx['receiver_pk']
            tx_object.order_id = algo_tx['order_id']
            tx_object.tx_id = txid      #txid is transaction id or tx_id??????????????????************
            # add it to the TX table
            g.session.add(tx_object)
            g.session.commit()


    # Add all transactions to the TX table (see models.py) ************************
    #When a transaction is successfully executed, i.e., when the exchange sends tokens to two counterparties
    # after matching an order, the exchange should record the following information in the transactions table
    # (the table ‘TX’).
    #platform: either ‘Ethereum’ or ‘Algorand’
    # receiver_pk: the address of the payee, i.e., the recipient of the tokens
    # order_id: the id of the order (in the Order table) that generated this transaction
    # tx_id: the transaction id of the payment transaction (from the Exchange) on the platform specified by platform

    # pass


""" End of Helper methods"""


@app.route('/address', methods=['POST'])
def address():
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
            #get_eth_keys(filename="eth_mnemonic.txt")  #******************
            eth_sk, eth_pk = get_eth_keys()

            return jsonify(eth_pk)

        if content['platform'] == "Algorand":
            # Your code here
            algo_sk, algo_pk = get_algo_keys() #******************

            return jsonify(algo_pk)


@app.route('/trade', methods=['POST'])
def trade():
    print("In trade", file=sys.stderr)
    connect_to_blockchains()
    #get_keys()           #************************** replace it with other two helper functions
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

        signature_check_flag = check_sig(content)  # 1. Check the signature

        if signature_check_flag:
            new_order = store_order(content)  # 2. Add the order to the table
            # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
            # ******************
            if check_transaction(new_order): #********************

                txes = order_fill(new_order)  # 3b. Fill the order (as in Exchange Server II) if the order is valid
                execute_txes(txes)  # 4. Execute the transactions  #******************
                return jsonify(True)
        else:
            log_message(content['payload'])
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
        #one_order_dict['signature'] = order.signature
        one_order_dict['tx_id'] = order.tx_id
        # print(one_order_dict)
        list_order.append(one_order_dict)

    result_dict['data'] = list_order

    return jsonify(result_dict)
    # Same as before
    # pass


if __name__ == '__main__':
    app.run(port='5002')
