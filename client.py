#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Feb 11 03:11:38 2020

@author: dell
"""

# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""
import socket
import threading
import pyDH
import tqdm
from Crypto.Cipher import DES3
from Crypto import Random
import os
import pickle
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
        
        
        
def make_pickle(opcode,s):
    packet=pack(opcode)
    packet.dumps(packet)
    s.send(packet)
    
def break_pickle(s):
    packet=s.recv(1024)
    packet=pickle.loads(packet)
    return packet   



def deffie(s):
    d1 = pyDH.DiffieHellman()
    
    d1_pubkey = d1.gen_public_key()
   
    
    
#    d1_pubkey=str(d1_pubkey)
    
    
#    beginning of strct part
    packet=pack(10)
#    print(d1_pubkey)
    packet.pubkey=d1_pubkey
    packet=pickle.dumps(packet)
    s.send(packet)
    
    
#    s.send(d1_pubkey.encode("utf-8"))
    
    d2_pubkey=s.recv(1024) #d2_pubkey received
    d2_pubkey=d2_pubkey.decode()
    d2_pubkey=int(d2_pubkey)
    
#    print("received d2_pubkey")
#    print(type(d1_pubkey))
    d1_sharedkey = d1.gen_shared_key(d2_pubkey)
    return d1_sharedkey
    



def file_handling(local_filename,s,cipher_decrypt,progress):
    with open(local_filename, 'wb+') as f:
        
        while True:
#            print('receiving data...')
            encrypted_text = s.recv(1024)
            s.send(bytes("received","utf-8"))
            temp_copy=cipher_decrypt.decrypt(encrypted_text)
            f.write(temp_copy)
            packet=s.recv(2048)
            packet=pickle.loads(packet)
            progress.update(len(encrypted_text))
#            print('data=%s', (ravi_copy.mp4))
            if packet.opcode==40:
                break
            
            
            
            print(packet.opcode)
    print('Successfully got the file')
    f.close()
    print('connection closed')
    
    
    
    
def main():
#   
    host = '127.0.0.1'
	# port=input()
    port=int(input())
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
    s.connect((host,port))
    d1_sharedkey=deffie(s)
    reqkey=""
    iv = Random.new().read(DES3.block_size) 
    print("iv: ",iv)
    s.send(iv)
    for i in range (0,24):
        reqkey=reqkey+d1_sharedkey[i]
#        print(reqkey)
#    msg1=s.recv(1024)
    iv_rec_msg=s.recv(1024)
#
    while 1:
        
        
        
        
        print("Enter File name")
        filename=input()
        packet=pack(20)
        packet.file_name=filename
        packet=pickle.dumps(packet)
        s.send(packet)
    #    s.send(filename.encode())
        file_status=s.recv(1024)
        file_status=file_status.decode()
        
        if(file_status=="found"):
            print("File Found on server")
            packet=pack(60)
            packet=pickle.dumps(packet)
            s.send(packet)
            
        else:
            print("File not Found on server")
            packet=pack(50)
            packet=pickle.dumps(packet)
            s.send(packet)
            s.close()
            exit()
        
        
        print(len(d1_sharedkey),reqkey)
        
#        print("Name Your file")
        local_filename="sns_copy.pdf"
    #   
        cipher_decrypt = DES3.new(reqkey, DES3.MODE_CFB, iv)
    #
        filesize = os.path.getsize(filename)
        progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    
    
    
    
    
        file_handling(local_filename,s,cipher_decrypt,progress)
        
        print("Do you want to download more files(y/n)?")
        ans=input()
        if(ans=="y"):
            packet=pack(20)
            packet=pickle.dumps(packet)
            s.send(packet)
            continue
        else:
            packet=pack(50)
            packet=pickle.dumps(packet)
            s.send(packet)
            break
    
    s.close()
#    f.close()
#    print('connection closed')

        
        


    

if __name__ == '__main__': 
	main() 
