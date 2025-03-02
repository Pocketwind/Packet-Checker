import pyshark
import scapy.all as scapy
import pandas as pd
import os
import numpy as np

FILE='p1'
FILE_PATH=f'./pcap/{FILE}.pcapng'
DEST_PATH=f'./feather/{FILE}.feather'

raw_data=scapy.rdpcap(FILE_PATH)

feather_data=pd.DataFrame(columns=['Protocol','Source','Destination','Length','Time'])

protocol=[]
source=[]
destination=[]
length=[]
time=[]
for p in raw_data:
    if p.haslayer(scapy.IP):
        protocol.append('IP')
        length.append(p[scapy.IP].len)
    elif p.haslayer(scapy.TCP):
        protocol.append('TCP')
        length.append(p[scapy.TCP].len)
    elif p.haslayer(scapy.UDP):
        protocol.append('UDP')
        length.append(p[scapy.UDP].len)
    else:
        protocol.append('Other')
        length.append(0)
    source.append(p.src)
    destination.append(p.dst)
    time.append(p.time)

feather_data['Protocol']=protocol
feather_data['Source']=source
feather_data['Destination']=destination
feather_data['Length']=length
feather_data['Time']=time

feather_data.to_feather(DEST_PATH)