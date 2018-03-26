'''
Created on 9 Feb 2018

@author: Stephen
'''
import csv
import time
import pyshark
from timeit import default_timer as timer

def main():
        
        cap = pyshark.LiveCapture(interface= 'WiFi 2')
        cap.sniff_continuously(packet_count=None)

        def get_ip_layer_name(pkt):
            for layer in pkt.layers:
                if layer._layer_name == 'ip':
                    return 4
                elif layer._layer_name == 'ipv6':
                    return 6




        def csv_interval_gather(cap): # creates/rewrites 'test.csv' file - writes header row - goes through packets, writing a row to the csv for each packet
            start_time = time.time()
            with open ('test.csv', 'w', newline='') as csvfile:
                filewriter = csv.writer(csvfile, delimiter=',' , quotechar='|', quoting=csv.QUOTE_MINIMAL)
                filewriter.writerow(['Packet', 'IP Source', 'IP dest', 'Time', 'Packets/Time', 'target' ])
                tcp_count = 0
                udp_count = 0
                icmp_count = 0
                other_count = 0
                
                i = 0
                start = timer()
                for pkt in cap:                
                    print ("Time: ", time.time() - start_time)
                    i += 1
                    end = timer()
                    if (end - start <= 5):
                        print("Packets Collected:", i)
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
                    else:
                        return

        
        csv_interval_gather(cap)
    
main()