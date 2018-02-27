'''
Created on 11 Feb 2018

@author: Stephen
'''

import pyshark
import time
from elasticsearch import transport

def main():
        cap = pyshark.LiveCapture(interface= 'WiFi 2')
        cap.sniff_continuously(packet_count=None)
        def infogather(cap):
            start_time = time.time()
            packet_number = 0
                    
        def get_highest_layer(pkt):
            for pkt in cap:
                if pkt.transport_layer == 'TCP':
                   # print(pkt.transport_layer, "\n")
                    return (pkt.transport_layer)
                elif pkt.transport_layer == 'UDP':
                   # print(pkt.transport_layer, "\n")
                    return (pkt.transport_layer)
                elif pkt.highest_layer == 'ICMP':
                  #  print(pkt.highest_layer, "\n")
                    return (pkt.transport_layer)
                        
        def get_transport_layer(pkt):
           for transport in pkt.transport_layer:
                if transport == 'T':
                    return 'TCP'
                elif transport == "U":
                    return 'UDP'
                elif transport != 'U' or 'T':
                    return transport
                    print(transport)

                                      
        def get_ip_layer_name(pkt):
            for layer in pkt.layers:
                if layer._layer_name == 'ip':
                    return 4
                elif layer._layer_name == 'ipv6':
                    return 6
                elif layer._layer_name == 'ARP':
                    return 'ARP'
        
        def packet_info(cap): # Goes through each packet in capture or live_capture.
            start_time = time.time()
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
                    print(get_highest_layer(pkt))
                    print ('Packet %d' % i)
                    print (pkt.highest_layer)
                    print (pkt.transport_layer)
                    print ('Time', pkt.sniff_time)
                    print ('Layer: ipv%d' % get_ip_layer_name(pkt))
                    print ('Source IP:', ip.src)
                    print ('Destination IP:', ip.dst)
                    print ('Source Port: ', pkt[pkt.transport_layer].srcport)
                    print ('Destination Port: ', pkt[pkt.transport_layer].dstport)
                    print (i/(time.time() - start_time))
                    print ('')
                else:
                    print('ARP')             
            return               
        
        def build_up(cap):
            for pkt in cap:
                ip = None
                ip_layer = get_ip_layer_name(pkt)
                transport_layer = get_transport_layer(pkt)
                if ip_layer == 4:
                    ip = pkt.ip
                elif ip_layer == 6:
                    ip = pkt.ipv6                                             
                try:
                    transport_protocol = pkt.transport_layer
                    high_protocol = pkt.highest_layer
                    src_ip = ip.src
                    src_port = pkt[pkt.transport_layer].srcport
                    dst_ip = ip.dst
                    dst_port = pkt[pkt.transport_layer].dstport
 #                   print ("Working: " ,pkt.layers, )
                    print(transport_protocol, src_ip, dst_ip, src_port, dst_port, "\n")
                    print(transport_layer)
                except AttributeError as e:
#                    pass
                    print("Broken: ", pkt.layers)
                    print(transport_protocol, high_protocol, ip_layer, "\n")

        def third_try(cap):
            i = 0
            start_time = time.time()            
            for pkt in cap:
                i += 1
                if get_highest_layer(pkt) == 'TCP' or 'UDP':
                    ip = None
                    ip_layer = get_ip_layer_name(pkt)
                    if ip_layer == 4:
                        ip = pkt.ip
                    elif ip_layer == 6:
                        ip = pkt.ipv6
                    print(get_highest_layer(pkt))
                    print ('Packet %d' % i)
                    print (pkt.highest_layer)
                    print (pkt.transport_layer)
                    print ('Time', pkt.sniff_time)
                    print ('Layer: ipv%d' % get_ip_layer_name(pkt))
                    print ('Source IP:', ip.src)
                    print ('Destination IP:', ip.dst)
#                    print ('Source Port: ', pkt[pkt.transport_layer].srcport)
#                    print ('Destination Port: ', pkt[pkt.transport_layer].dstport)
                    print (i/(time.time() - start_time))
                    print ('')
                else:
                    print  (pkt.layer.field_names)               
            
                
#                print (pkt.highest_layer)
 #               print (pkt.transport_layer, "\n")
        packet_info(cap)
#        build_up(cap)
 #       third_try(cap)
main()    