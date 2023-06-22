#!/usr/bin/env python3
from caproto.sync.shark import shark
import dpkt
from ctypes import *
import os
import logging
import concurrent.futures


class go_string(Structure):
    _fields_ = [
        ("p", c_char_p),
        ("n", c_int)]


def remove(myFile):
    if os.path.isfile(myFile):
        os.remove(myFile)


def parse_pcap(pcapFile):
    td = 0.0
    times = list()
    with open(pcapFile, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        for ts, buf in pcap:
            
            times.append(ts)
    
    if len(times) > 1:
        td = times[1] - times[0]
        td = round(td)
    
    return td


def run(ip, port, pcapFile):
    
    port = str(port)
    go_ip = bytes(ip, 'utf-8')
    go_ip = go_string(c_char_p(go_ip), len(go_ip))
    port = bytes(port, 'utf-8')
    port = go_string(c_char_p(port), len(port))
    inFile = bytes(pcapFile, 'utf-8')
    inFile = go_string(c_char_p(inFile), len(inFile))
    
    lib.runTcpDump(go_ip, inFile, port)


def compute_td(dst_ip, dst_port):
    try:
        pcapFile = "./retran_time_"+dst_ip+".pcap"
        run(dst_ip, dst_port, pcapFile)
        td = parse_pcap(pcapFile)
        
        remove(pcapFile)
    except Exception as err:
        logging.error(err)
        return 0.0
    return td


def compute_tds(services):
    tds = list()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for service in services:
            fields = service.split(':')
            dst_ip = fields[0]
            dst_port = int(fields[1])
            futures.append(executor.submit(compute_td, dst_ip, dst_port))
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            tds.append(res)
    return tds


lib = cdll.LoadLibrary("./ipid_pred_lib.so")
logging.basicConfig(level=logging.INFO, filename='./parse_pcap.log')


def main():
    '''
    f = open('./ooni_ip_blocking_2022_final.dat', 'w')
    with open('./ooni_ip_blocking_2022_final.csv', 'r') as filehandle:	
            filecontents = filehandle.readlines()
            for i in range(10):
                    for line in filecontents:
                            fields = line.split(",")
                            if len(fields) < 4: continue
                            ip = fields[4]
                            port = fields[5].strip('\n')
                            port = int(port)
                            pcapFile = "./retran_time_"+ip+".pcap"
                            run(ip, port, pcapFile)
                            td = parse_pcap(pcapFile)
                            remove(pcapFile)
                            if td == 0: continue
                            string = line.strip('\n')+','+str(td)+'\n'
                            f.write(string)
    f.close()
    '''
    services = list()
    with open('./ooni_ip_blocking_2022_test_list.csv', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            fields = line.split(",")
            if len(fields) < 7:
                continue
            ip = fields[4]
            port = fields[5]
            service = ip + ':'+port
            if service in services:
                continue
            services.append(service)
    tds = compute_tds(services)
    print(tds)


if __name__ == "__main__":
    # execute only if run as a script
    main()
