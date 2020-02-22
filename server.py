#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Feb 11 03:11:13 2020

@author: dell
"""



import socket
import tqdm
#import thread  
import threading
from _thread import *
from threading import Thread
import pyDH
import os
import pickle 
from Crypto.Cipher import DES3
from Crypto import Random
import os.path
from os import path




def found(path):
    dir_path = os.path.dirname(os.path.realpath(__file__)) 
  
    for root, dirs, files in os.walk(dir_path): 
        for file in files:  
            if path in file: 
                return True
            else:
                return False




class pack: 
  
    def __init__(self, opcode): 
        self.opcode = opcode
        self.source_addr="127.0.0.1"
        self.dest_addr="127.0.0.1"
        self.pubkey=0
        self.sharedkey=0
        self.msg=""
        self.file_msg=bytearray()
        self.file_name=""
        
    
#        self.src =src
#        self.dest=dest
def make_pickle(opcode,s):
    packet=pack(opcode)
    packet.dumps(packet)
    s.send(packet)
    
def break_pickle(s):
    packet=s.recv(1024)
    packet=pickle.loads(packet)
    return packet   
def deffie(c):
    d1_pubkey =c.recv(1024)
    
    
    d1_pubkey=pickle.loads(d1_pubkey)
    d1_pubkey=d1_pubkey.pubkey
    print(d1_pubkey)
    
    
    
#    d1_pubkey.decode("utf-8")
    
    
    d2 = pyDH.DiffieHellman()
    d2_pubkey = d2.gen_public_key()
    d2_pubkey=str(d2_pubkey)
    c.send(d2_pubkey.encode())
    d1_pubkey=int(d1_pubkey)
    
    d2_sharedkey = d2.gen_shared_key(d1_pubkey)
    print(d2_sharedkey)
    return d2_sharedkey

def file_handling(filename,c,cipher_encrypt):
    print("sending")
    f = open(filename,'rb+')
    plaintext = f.read(1024)
    
    while (plaintext):
        encrypted_text = cipher_encrypt.encrypt(plaintext)
        c.send(encrypted_text)
        msg=c.recv(1024)
#        print('Sent ',repr(l))
        plaintext = f.read(1024)
        
        if(len(plaintext)):
            packet=pack(30)
            packet=pickle.dumps(packet)
            c.send(packet)
            
        else:
            packet=pack(40)
            packet=pickle.dumps(packet)
            c.send(packet)
            
            
        
    f.close()
    
    
def threaded(c):
##    pl=3
##    print(pl)
    
    d2_sharedkey=deffie(c)
    
    reqkey=""
    for i in range (0,24):
        reqkey=reqkey+d2_sharedkey[i]
        
    iv = c.recv(1024)
    c.send(bytes("iv received","utf-8"))
    
    
    while 1:
        packet=c.recv(1024)
        packet=pickle.loads(packet)
        filename=packet.file_name
    #    filename=filename.decode()
        print(path.exists(filename))
        if(path.exists(filename)):
            fd="found"
            print("found")
            c.send(fd.encode())
        else:
            fd="not found"
            print("not found")
            c.send(fd.encode())
            
        packet=c.recv(1024)
        packet=pickle.loads(packet)
        if(packet.opcode==50):
            print("Disconnection msg genereated by Client")
            c.close()
            exit()
        
        print(filename,type(filename))
        print(iv)
        cipher_encrypt = DES3.new(reqkey, DES3.MODE_CFB, iv)
        print(reqkey)
        
        
        print(iv)
        
        file_handling(filename,c,cipher_encrypt)
    #    filename='server.py'
        x=c.recv(1024)
        x=pickle.loads(x)
        
        if(x.opcode==50):
            break
            c.close()
        else:
            continue




def Main(): 
    
    host = "" 
    port=int(input())
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    s.bind((host, port)) 
    print("socket binded to port", port) 
    s.listen(5) 
    print("socket is listening") 

    while True:

        
        c, addr = s.accept()
        print('Connected to :', addr[0], ':', addr[1]) 

        start_new_thread(threaded, (c,)) 
    
    s.close()

if __name__ == '__main__': 
	Main() 