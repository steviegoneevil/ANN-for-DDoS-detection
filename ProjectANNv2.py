'''
Created on 02 Feb 2018

@author: Stephen
'''
from io import StringIO
import winreg # to use windows registry to ID guids given by netifaces
import netifaces # used to identify netwrok interafces on a system and returning the ocrresponding guid
import pickle # used to save the model for further testing and use
import csv #python standard for csv work
import pyshark # tshark wrapper used to capture and parse packets
import sys
import time
import pandas # data handler
from pyshark import packet
from builtins import int
from pprint import pprint
from sklearn.preprocessing import OneHotEncoder

def main():
        int = netifaces.interfaces()
        #cap = pyshark.FileCapture('test.pcap') # For training 

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
                for pkt in cap:
                    i += 1  
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
                    else:
                        print('ARP')             
                return
            except KeyboardInterrupt:
                pass
       
        def csvtest(cap): # creates/rewrites 'test.csv' file - writes header row - goes through packets, writing a row to the csv for each packet
            with open ('test.csv', 'w', newline='') as csvfile:
                filewriter = csv.writer(csvfile, delimiter=',' , quotechar='|', quoting=csv.QUOTE_MINIMAL)
                filewriter.writerow(['Packet', 'IP Source', 'IP dest', 'Time', 'Packets/Time', 'target' ])
                tcp_count = 0
                udp_count = 0
                icmp_count = 0
                other_count = 0
                
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
         
         
         
        def int_names(int_guids):               
            int_names = int_names = ['(unknown)' for i in range(len(int_guids))]
            reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            reg_key = winreg.OpenKey(reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
            for i in range(len(int_guids)):
                try:
                    reg_subkey = winreg.OpenKey(reg_key, int_guids[i] + r'\Connection')
                    int_names[i] = winreg.QueryValueEx(reg_subkey, 'Name')[0]
                except FileNotFoundError:
                    pass
            return int_names
        
        
        def csv_data_check():
            data = pandas.read_csv('test.csv', delimiter=',')
            read_choice = input("""How would you like to view the data?
                                
                                All (a)
                                Numerical Only (n)
                                Categorical Only (c)
                                
                                """)
            if read_choice == "a":
                print(data)
            elif read_choice == "n":
                print(data._get_numeric_data())
            elif read_choice == "c":
                print(data.select_dtypes(include='object'))

        def MLP():

            l_data = input("Name of CSV file")
            
            load = input("Load model?")
            if load == 'y':
                filename = input("Filename to load?")
                loaded_model = pickle.load(open(filename, 'rb'))
                print(loaded_model.coefs_)
                print(loaded_model.loss_)

            else:   
            
                data = pandas.read_csv(l_data, delimiter=',') # reads CSV 
                data = data._get_numeric_data() #parses only numerical data in csv
                
                print(data) # entire block for testing and checking values
                print(data.keys())
                #print(data[['Packet','Packets/Time']])
                #print(data['target'])
                
                X = data[['Packet','Packets/Time']] # Data used to train
                y = data['target'] # targets for the MLP
                
                from sklearn.model_selection import train_test_split
                from sklearn.preprocessing import StandardScaler
                X_train, X_test, y_train, y_test = train_test_split(X, y)
                scaler = StandardScaler()
                
                scaler.fit(X_train)
                X_train = scaler.transform(X_train)
                X_test = scaler.transform(X_test)
                
                print(X_train)
                print(X_train)
                
                from sklearn.neural_network import MLPClassifier
                
                mlp = MLPClassifier(hidden_layer_sizes=(5), activation='logistic') # number of hidden layers = 1 layer of 10 nodes
                mlp.fit(X_train, y_train)
                print(mlp.predict(X_test))
                
                
                predictions = mlp.predict(X_test)
                
                from sklearn.metrics import classification_report,confusion_matrix
                print(confusion_matrix(y_test,predictions))
                print (classification_report(y_test,predictions))
    
                ci = input("do you want to see weights and intercepts?")
                if ci == 'y':
                    print(mlp.coefs_)
                    print(mlp.intercepts_)
                else:
                    pass
                
                save = input("Save model?")
                if save == 's':
                            filename = input("Filename for saving?")
                            pickle.dump(mlp, open(filename, 'wb'))
        

            
        ans=True
        
        while ans:
            print ("""
            1. Visual Packet Sniffer
            2. ANN Data gatherer
            3. Neural Network
            4. Data Check
            5. Exit
            """)

            ans = input("What would you like to do? ") 
            if ans=="1":
                for i, value in enumerate(int_names(int)):
                    print(i, value)
                print('\n')
                t = input("Please select interface: ")
                cap = pyshark.LiveCapture(interface= t)
                cap.sniff_continuously(packet_count=None)            
                packet_info(cap)
            elif ans=="2":
                for i, value in enumerate(int_names(int)):
                    print(i, value)
                print("\n")
                t = input("Please select interface: ")
                cap = pyshark.LiveCapture(interface= t)
                cap.sniff_continuously(packet_count=None)   
                print("Now Gathering data....")
                csvtest(cap)
            elif ans=="3":
                MLP()
            elif ans =="4":
                csv_data_check()
            elif ans == "5":
                break
main()