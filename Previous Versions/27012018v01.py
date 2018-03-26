'''
Created on 27 Jan 2018

@author: Stephen
'''
from io import StringIO
import csv
import pyshark
import sys
import time
import pandas
from pyshark import packet
from builtins import int

def main():
    
        #cap = pyshark.FileCapture('test.pcap') # For training 
        cap = pyshark.LiveCapture(interface= 'WiFi 2')
        cap.sniff_continuously(packet_count=None)
        start_time = time.time()
        def get_ip_layer_name(pkt):
            for layer in pkt.layers:
                if layer._layer_name == 'ip':
                    return 4
                elif layer._layer_name == 'ipv6':
                    return 6
        
        def packet_info(cap): # Goes through each packet in capture or live_capture.
            try:
                i = 1
                for pkt in cap:# 
                    if pkt.highest_layer != 'ARP':
                        ip = None
                        ip_layer = get_ip_layer_name(pkt)
                        if ip_layer == 4:
                            ip = pkt.ip
                        elif ip_layer == 6:
                            ip = pkt.ipv6
                        print ('Packet %d' % i)
                        print (pkt.highest_layer)
                        print (pkt.transport_layer)
                        print ('Time', pkt.sniff_time)
                        print ('Layer: ipv%d' % get_ip_layer_name(pkt))
                        print ('Source IP:', ip.src)
                        print ('Destination IP:', ip.dst)
                        print (i/(time.time() - start_time))
                        print ('')
                        i += 1
                    else:
                        i += 1
                        print('ARP')          
                return
            except KeyboardInterrupt:
                pass
            
        def csvtest(cap):
            try:
                with open ('test.csv', 'w', newline='') as csvfile:
                    filewriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                    filewriter.writerow(['Packet', 'IP Source', 'IP dest', 'Time', 'Packets/Time', 'target'])
                    
                    i = 0
                    for pkt in cap:
                        i += 1
                        if pkt.highest_layer != 'ARP':
                            ip = None
                            ip_layer = get_ip_layer_name(pkt)
                            if ip_layer == 4:
                                ip = pkt.ip
                                ipv = 0 # target test
                            elif ip_layer == 6:
                                ip = pkt.ipv6
                                ipv = 1 # target test
                            filewriter.writerow([i, ip.src, ip.dst, pkt.sniff_time, i/(time.time() - start_time), ipv ])
            except KeyboardInterrupt:
                pass
                        
                        
                        
        def MLP():
            print(__doc__)
            data = pandas.read_csv('test.csv', delimiter=',') # reads CSV 
            data = data._get_numeric_data() #parses only numerical data in csv
            
            print(data) # entire block for testing and checking values
            print(data.keys())
            print(data[['Packet','Packets/Time']])
            print(data['target'])
            
            X = data[['Packet','Packets/Time']] # Data ysed to train
            y = data['target'] # targets for the MLP
            
            from sklearn.model_selection import train_test_split
            from sklearn.preprocessing import StandardScaler
            X_train, X_test, y_train, y_test = train_test_split(X, y)
            scaler = StandardScaler()
            
            scaler.fit(X_train)
            X_train = scaler.transform(X_train)
            X_test = scaler.transform(X_test)
            
            from sklearn.neural_network import MLPClassifier
            
            mlp = MLPClassifier(hidden_layer_sizes=(10), activation='logistic') # number of hidden layers = 1 layer of 10 nodes
            mlp.fit(X_train, y_train)
            print(mlp.predict(X_test))
            
            
            predictions = mlp.predict(X_test)
            
            from sklearn.metrics import classification_report,confusion_matrix
            print(confusion_matrix(y_test,predictions))
            print (classification_report(y_test,predictions))
            print(mlp.coefs_)
            print(mlp.intercepts_)
            
            ci = input("do you want to see weights and intercepts?")
            if ci == 'y':
                print(mlp.coefs_)
                print(mlp.intercepts_)
            else:
                pass
            
        ans=True
        while ans:
            print ("""
            1.Visual Packet Sniffer
            2.ANN Data gatherer
            3.Neural Network
            4.Exit
            """)
            ans = input("What would you like to do? ") 
            if ans=="1":
                packet_info(cap)
            elif ans=="2":
                csvtest(cap)
                print("Now Gathering data....")
            elif ans=="3":
                MLP()
            elif ans =="4":
                break
            
main()