import os
import sys
import hashlib
import argparse
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

def get_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-port', type=int, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-c', action='store_true')
    group.add_argument('-s', action='store_true')
    args = parser.parse_args()
    return args

def padding(data):
    """Add a padding to data for future RSA 2048 encrypting.
    Keyword arguments:
    data -- data to be encrypted without padding
    """
    padding_len = 256 - len(data)
    padding = os.urandom(padding_len - 3)
    padding.replace(b'0', b'9')
    padding = b'0' + b'0' + padding + b'0'
    return padding + data

def RSA_encrypt(data, key, sign):
    """Basic RSA encrypt.
    Keyword arguments:
    data -- encrypted data (with padding)
    key -- RSA public or private key
    sign -- True if data is being signed with sender's private key
    """
    if sign:
        msg = pow(int.from_bytes(data, "big"), key.d, key.n)
    else:
        msg = pow(int.from_bytes(data, "big"), key.e, key.n)
    return msg.to_bytes(256, "big")

def RSA_decrypt(data, key, sign):
    """Basic RSA decrypt.
    Keyword arguments:
    data -- encrypted data (with padding)
    key -- RSA public or private key
    sign -- True if data is being signed with sender's private key
    """
    if sign:
        msg = pow(int.from_bytes(data, "big"), key.e, key.n)
    else:
        msg = pow(int.from_bytes(data, "big"), key.d, key.n)
    return msg.to_bytes(256, "big")


args = get_args()
if (args.c): ## Client
    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sck.settimeout(600)
    try:
        sck.connect(("localhost", args.port))
    except socket.error:
        sys.exit("Error connecting to the server: {}.".format(socket.error))
    print("\nc: Successfully connected to server")

    ## RSA keys
    f_cpr = open('./cert/client_private.pem','r')
    key_cpr = RSA.import_key(f_cpr.read())
    f_cpu = open('./cert/client_public.pem','r')
    key_cpu = RSA.import_key(f_cpu.read())
    f_spu = open('./cert/server_public.pem','r')
    key_spu = RSA.import_key(f_spu.read())
    print("\nc: RSA_public_key_sender={}".format(key_cpu.export_key()))
    print("\nc: RSA_private_key_sender={}".format(key_cpr.export_key()))
    print("\nc: RSA_public_key_receiver={}".format(key_spu.export_key()))

    while True:
        ## Data input
        data = input('Enter input: ')
        data = data.encode()
        ## AES key and IV
        AES_key = os.urandom(16)
        AES_iv = os.urandom(16)
        print("\nc: AES_key={}".format(AES_key))
        print("\nc: AES_key={}".format(AES_iv))
        AES_key_padding = padding(AES_key + AES_iv)
        print("\nc: AES_key_padding={}".format(AES_key_padding))
        RSA_AESkey = RSA_encrypt(AES_key_padding, key_spu, False)
        ## Checksum
        checksum = hashlib.md5(data).digest()
        print("\nc: MD5={}".format(checksum))
        checksum = padding(checksum)
        print("\nc: MD5_padding={}".format(checksum))
        RSA_checksum = RSA_encrypt(checksum, key_cpr, True)
        print("\nc: RSA_MD5_hash={}".format(RSA_checksum))
        ## Message and checksum
        checked_msg = data + RSA_checksum
        cipher = AES.new(AES_key, AES.MODE_OFB, AES_iv)
        msg = cipher.encrypt(checked_msg)
        print("\nc: AES_cipher={}".format(msg))
        print("\nc: RSA_AES_key={}".format(RSA_AESkey))
        msg = msg + RSA_AESkey
        print("\nc: ciphertext={}".format(msg))
        ## Send message
        while True:
            sck.send(len(msg).to_bytes(2, 'big', signed=False))
            sck.sendall(msg)
            res = sck.recv(2)
            res = int.from_bytes(res, 'big')
            if res == 1:
                print("The message was successfully delivered.")
                break
            else:
                print("The message was sent again.")
elif args.s: ## Server
    ## Listen for a client
    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sck.bind(("localhost", args.port))
    sck.listen(1)
    conn, address = sck.accept()
    print("\ns: Client has joined")
    ## RSA keys
    f_spr = open('./cert/server_private.pem','r')
    key_spr = RSA.import_key(f_spr.read())
    f_spu = open('./cert/server_public.pem','r')
    key_spu = RSA.import_key(f_spu.read())
    f_cpu = open('./cert/client_public.pem','r')
    key_cpu = RSA.import_key(f_cpu.read())
    print("\ns: RSA_public_key_receiver={}".format(key_spu.export_key()))
    print("\ns: RSA_private_key_receiver={}".format(key_spr.export_key()))
    print("\ns: RSA_public_key_sender={}".format(key_cpu.export_key()))
    while True:
        ## Get data
        msg_len = conn.recv(2)
        msg_len = int.from_bytes(msg_len, 'big')
        msg = conn.recv(4096)
        if msg_len != len(msg):
            print("\ns: The integrity of the report has been compromised.")
            conn.send((0).to_bytes(2, 'big', signed=False))
            continue
        print("\ns: ciphertext={}".format(msg))
        ## Get AES information
        AESdata = msg[len(msg)-256:]
        print("\ns: RSA_AES_key={}".format(AESdata))
        AESdata = RSA_decrypt(AESdata, key_spr, False)
        AES_key = AESdata[len(AESdata)-32:len(AESdata)-16]
        AES_iv = AESdata[len(AESdata)-16:]
        print("\ns: AES_key={}".format(AES_key))
        print("\ns: AES_iv={}".format(AES_iv))
        ## Get message and checksum
        checked_msg = msg[:len(msg)-256]
        print("\ns: AES_cipher={}".format(checked_msg))
        cipher = AES.new(AES_key, AES.MODE_OFB, AES_iv)
        checked_msg = cipher.decrypt(checked_msg)
        print("\ns: text_hash={}".format(checked_msg))
        checksum_rcv = checked_msg[len(checked_msg)-256:]
        checksum_rcv = RSA_decrypt(checksum_rcv, key_cpu, True)
        checksum_rcv = checksum_rcv[len(checksum_rcv)-16:]
        data = checked_msg[:len(checked_msg)-256]
        checksum = hashlib.md5(data).digest()
        print("\ns: plaintext={}".format(data))
        print("\ns: MD5={}".format(checksum))
        if checksum == checksum_rcv:
            print("\ns: The integrity of the message has not been compromised.")
            conn.send((1).to_bytes(2, 'big', signed=False))
        else:
            print("\ns: The integrity of the report has been compromised.")
            conn.send((0).to_bytes(2, 'big', signed=False))
    else:
        sys.exit("Invalid value.")
