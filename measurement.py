#!/usr/bin/env python3
from numpy import array, asarray
import numpy as np
from sklearn.metrics import mean_squared_error
from math import sqrt
from sklearn import datasets, preprocessing
import time
import decimal
import threading
from ctypes import *
import math
import statistics
from scipy.stats import norm, linregress
from ipid_censor_or_spoof_lib import single_ipid_test_for_censor, single_ipid_test_for_spoof, probe, compute_td
from ipid_online_analysis_lr import predict_ipids, single_ip_forecast
import logging.config
import logging
import argparse
from datetime import date, datetime

from ipid_censor_or_spoof_lib import probe, compute_td
import random
import subprocess
import multiprocessing
import pickle
from collections import defaultdict, Counter
import concurrent.futures
import ipaddress
import os
import glob
import os.path
import pandas as pd



def validate_ipv4_address(ip_string):
    try:
        ip_object = ipaddress.IPv4Address(ip_string)
        return True
    except ValueError:
        return False
      
def load_vantage_points(ifile):

    clients = set()
    with open(ifile, 'r') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 1:
                continue
            ip = fields[0].strip('\n')
            if not validate_ipv4_address(ip) or len(ip.split('.')) != 4:
                continue
            clients.add(ip)

    return list(clients)

def test_ipids(sip0, sip1, ip, protocol, flag, port, ns, ofile1):
    code = 0
    count = 0
    n = 1
    for i in range(n):
        ipid = probe(sip0, ip, protocol, flag, port, ns)

        if ipid < 0:
            count = count+1  # -1
    if count == n:
        code = 1  # unreachable
        return ip, code

    res = predict_ipids(sip0, sip1, ip, protocol, flag,
                        port, ns, '1', '10')  # fs = 1, sl = 10

    if res != 1:
        code = 2  # inapplicable
        return ip, code
        
    '''
    code, pred, n = single_ip_forecast(
        sip0, sip1, ip, protocol, flag, port, ns, None, None)
    '''  
    '''
    if pred > 0:
        code = 3
        return ip, code
    '''
    '''
    if pred < 0.95 or n > 10 or n < 1:
        code = 3  # insuitable
        return ip, code
    '''

    return ip, code
  
def filter_clients(clients, note, sip0, sip1, proto, port, flag, of):
    no_res = list()
    clients = list(clients)
    random.shuffle(clients)

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for client in clients:
            ip = client
            if note == 'ipid':
                protocol = proto

                ns = ''
                futures.append(executor.submit(
                    test_ipids, sip0, sip1, ip, protocol, flag, port, ns, of))  # should be test_ipids!!!!
        for future in concurrent.futures.as_completed(futures):
            ip, code = future.result()
            if code != 0:
                continue
            of.write(ip+'\n')
            
def test_servers(sip0, sip1, ip, protocol, flag, port, ns, ofile1):
    count = 0
    port = 0
    n = 3

    for i in range(n):
        ipid = probe(sip0, ip, 'tcp', 'S', int(80), ns)

        if ipid < 0:
            count = count+1  # -1
    if count < n:
        port = 80
        return ip, port

    for i in range(n):
        ipid = probe(sip0, ip, 'tcp', 'S', int(443), ns)
        if ipid < 0:
            count = count+1  # -1
    if count < n:
        port = 443

    return ip, port     
  
def filter_servers(servers, note, sip0, sip1, proto, port, flag, ofile):
    no_res = list()
    un = 0
    servers = list(servers)
    # random.shuffle(servers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for server in servers:
            ip = server
            if note == 'ipid':
                protocol = proto

                ns = 'www.google.com'
                futures.append(executor.submit(
                    test_servers, sip0, sip1, ip, protocol, flag, port, ns, ofile))  # should be test_ipids!!!!
        for future in concurrent.futures.as_completed(futures):
            ip, port = future.result()

            if port == 0:
                continue
            ofile.write(ip+','+str(port)+'\n') 
            
def start_ipid_ip_spoof(sip0, sip1, proto, port, flag, servers, dataset, ofile):
    protocol = proto
    #port = random.randrange(10000, 65535, 1)
    ns = ''
    cu = ''
    asn = ''
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for ip in servers:
            g = ip.split(".")
            if len(g) < 4:
                continue
            fake_ip = g[0] + '.' + g[1]+'.' + g[2]+'.'+str((int(g[3])+1) % 256)
            futures.append(executor.submit(single_ipid_test_for_spoof,
                                           cu, asn, sip0, sip1, ip, fake_ip, protocol, port, flag, ns, 30, True, dataset, ofile))  # True
        for future in concurrent.futures.as_completed(futures):
            future.result()
            #print('code: ', code)
            
def ip_spoof_via_ipids(ifile, dataset, ofile1, ofile2):
    files = os.path.join(ifile, "*")
    files = glob.glob(files)
    of = open(ofile1, 'w')
    for ifile in files:
        
        #random.randrange(10000, 65535, 1)
        servers = load_vantage_points(ifile)  # ipv4 servers
        proto, port, flag = 'tcp', int(
            random.randrange(10000, 65535, 1)), 'SA'  # ????
        sip0, sip1 = '45.125.236.166', '45.125.236.167'
        
        #applicable ip servers
        filter_clients(servers, 'ipid', sip0, sip1, proto, port, flag, of)
        
        #start_ipid_ip_spoof(sip0, sip1, proto, port, flag, servers, dataset, ofile2)
    of.close()
    
def sav():
    dataset1 = {}
    ifile = './SAV/'
    # scanning with TCP SA random ports
    ofile1 = './tcp_random_infra_vps.dat'
    ofile2 = ''
    ip_spoof_via_ipids(ifile, dataset1, ofile1, ofile2)

def load_websites(ifile):
    servers = list()

    with open(ifile, "rb") as f:
        websites = pickle.load(f)
        for ip in websites:
            servers.append(ip)

    return servers
  
def censor_measure_via_ipids(vpsfile, websitesfile, dataset, ofile1, ofile2):
    proto, port, flag = 'tcp', int(
        random.randrange(10000, 65535, 1)), 'SA'  # ????
    sip0, sip1 = '45.125.236.166', '45.125.236.167'

    #clients = load_vantage_points(vpsfile)  # ipv4 servers
    #of = open(ofile1, 'w')
    #filter_clients(clients, 'ipid', sip0, sip1, proto, port, flag, of)
    clients = load_vantage_points(ofile1)
    print('vps: ', len(clients))
    random.shuffle(clients)
    '''
    servers = load_websites(websitesfile)
    filter_servers(servers, 'ipid', sip0, sip1, proto, port, flag, ofile2)
    servers = load_list_for_ip(websitesfile)
    test_tds(sip0, servers, ofile2)
    '''
    
    
    servers = load_list_for_ip(websitesfile)
    print('servers: ', len(servers))
    random.shuffle(servers)
    n1 = len(servers)
    n2 = len(clients)
    n = int(n1/n2)
    for i in range(n):
        subclients = clients
        start = i*n2
        end = (i+1) * n2
        subservers = servers[start:end]
        start_ipid_censor_measure(
            sip0, sip1, proto, port, flag, subclients, subservers, dataset, ofile2)

    rest = n1 % n2
    if rest > 0:
        subclients = clients[0:rest]
        subservers = servers[-rest:]
        start_ipid_censor_measure(
            sip0, sip1, proto, port, flag, subclients, subservers, dataset, ofile2)
        
def censorship():
    dataset1 = {}
    path = './censorship/'
    vpsfile = path + 'tcp_random_any_vps_RU.dat'
    #russia_blocked_alive_servers_tds.dat, top_undertest_alive_servers_tds.dat
    # top_undertest_websites.p
    websitesfile = path + 'CLBL_alive_servers_tds.dat'
    #websitesfile = path + 'russia_blocked_websites.p'
    ofile1 = path + 'tcp_random_suitable_vps_RU.dat'

    # russia_blocked_measure.res
    ofile2 = open(path + 'CLBL_measure.res', 'w')
    censor_measure_via_ipids(vpsfile, websitesfile, dataset1, ofile1, ofile2)
    ofile2.close()

  
def main():
    
    # prepare_CLBL_sites()
    # prepare_alive_servers()
    # plot_predictability()
    # prepare_top_domains()
    # sav()
    # censorship()


if __name__ == "__main__":
    # execute only if run as a script
    main()
