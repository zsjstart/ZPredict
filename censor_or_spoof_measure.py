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
import concurrent.futures
import pandas as pd
import math
import statistics
from scipy.stats import norm, linregress
import random
from ipid_censor_or_spoof_lib import single_ipid_test_for_censor, single_ipid_test_for_spoof, probe, predict_ipids, my_compute_td
import logging.config
import logging
import argparse
from datetime import date, datetime

def count_unique_ip(ifile, list_type):
	test_list = list()
	with open(ifile, 'r') as filehandle:
		filecontents = filehandle.readlines()
		for i, line in enumerate(filecontents):
			fields = line.split(",")
			if len(fields) < 4: continue
			cls = fields[0]
			if cls != list_type: continue
			ip = fields[2]
			if ip in test_list: continue
			test_list.append(ip)
	return test_list

def count_local_ip(cu, ifile, measure_type):
	local_list = list()
	cls = 'local'
	with open(ifile, 'r') as filehandle:
		filecontents = filehandle.readlines()
		for i, line in enumerate(filecontents):
			fields = line.split(",")
			if len(fields) < 4: continue
			if cu not in fields[0]: continue
			if measure_type == "ipid":
				ip = fields[2]
				if ip in local_list: continue
				local_list.append(ip)
	return local_list
	
def load_list_for_ip(ifile, list_type):
	test_list = list()
	with open(ifile, 'r') as filehandle:
		filecontents = filehandle.readlines()
		for i, line in enumerate(filecontents):
			fields = line.split(",")
			if len(fields) < 4: continue
			cls = fields[0]
			if cls != list_type: continue
			ip = fields[2]
			port = int(fields[3].strip('\n'))
			t = (cls, ip, port)
			if t in test_list: continue
			test_list.append(t)
	return test_list
	

def load_local_list(cu, ifile, measure_type):
	local_list = list()
	cls = 'local'
	with open(ifile, 'r') as filehandle:
		filecontents = filehandle.readlines()
		for i, line in enumerate(filecontents):
			fields = line.split(",")
			if len(fields) < 4: continue
			if cu not in fields[0]: continue
			if measure_type == "ipid":
				ip = fields[2]
				port = int(fields[3].strip('\n'))
				t = (cls, ip, port)
			if t in local_list: continue
			local_list.append(t)
	return local_list

def load_vantage_points(cu, ifile):
	dic = {}
	clients = list()
	with open(ifile, 'r') as filehandle:
		filecontents = filehandle.readlines()
		for i, line in enumerate(filecontents):
			fields = line.split(",")
			if len(fields) < 4: continue
			if cu not in fields[0]: continue
			asn = fields[1]
			ip = fields[3].strip('\n')
			if asn not in dic:
				dic[asn] = list()
			dic[asn].append(ip)
	clients = list()
	for asn in dic:
		t = (asn, dic[asn])
		clients.append(t)
	return clients
	
def load_open_resolvers(cu, ifile):
	dic = {}
	with open(ifile, 'r') as filehandle:
		filecontents = filehandle.readlines()
		for i, line in enumerate(filecontents):
			fields = line.split(",")
			if len(fields) < 4: continue
			if cu not in fields[0]: continue
			asn = fields[1]
			ip = fields[3].strip('\n')
			if asn not in dic:
				dic[asn] = list()
			dic[asn].append(ip)
	return dic

def start_ipid_ip_spoof(clients, dataset, ofile, cu, asn):
	protocol = 'tcp'
	port = random.randrange(10000, 65535, 1)
	ns = ''
	with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
		futures = []
		for client in clients:
			ip = client
			futures.append(executor.submit(single_ipid_test_for_spoof, cu, asn, ip, protocol, port, ns, 30, True, dataset, ofile))
		for future in concurrent.futures.as_completed(futures):
			future.result()
			#print('code: ', code)

def start_ipid_censor_measure(clients, servers, tds, dataset, ofile, cu, asn):
	protocol = 'tcp'
	port = random.randrange(10000, 65535, 1)
	ns = ''
	with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
		futures = []
		for client, server, td in zip(clients,servers, tds):
			ip = client
			cls = server[0]
			dst_ip = server[1]
			dst_port = int(server[2])
			futures.append(executor.submit(single_ipid_test_for_censor, cu, asn, ip, protocol, port, ns, cls, dst_ip, dst_port, 30, True, td, dataset, ofile))
		for future in concurrent.futures.as_completed(futures):
			code, dst_ip = future.result()
			#print('code: ', code)


def test_clients(clients, note):
	new_clients = list()
	with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
		futures = []
		for client in clients:
			ip = client
			if note == 'ipid':
				protocol = 'tcp'
				port = random.randrange(10000, 65535, 1)
				ns = ''
				futures.append(executor.submit(test_ipids, ip, protocol, port, ns))
		for future in concurrent.futures.as_completed(futures):
			ip, code = future.result()
			if code == 1: continue
			new_clients.append(ip)
	return new_clients
	
def test_ipids(ip, protocol, port, ns):
	code = 0
	count = 0
	for i in range(3):
		ipid = probe(ip, protocol, 'SA', port, ns)
		if ipid <= 0 : count = count+1 # -1 or 0
	if count == 3:
		logging.info('Client unreachable: {a}'.format(a= ip))
		code = 1
		return ip, code
	'''res = predict_ipids(ip, protocol,'SA', port, ns, 1, 10) # fs = 1, sl = 10
	if res != 1:
		logging.info('Not applicable: {a}, {res}'.format(a= ip, res=res))
		code = 1'''
	return ip, code

def compute_tds(sip, server):
	td = my_compute_td(sip, server)
	if td <= 0:
		logging.info('Web server unreachable: {a}'.format(a = server[1]))
		return td, server
	if td < 1:
		td = 1.0
	td = int(round(td))
	return td, server

#This function is used to remove servers that are non-responsive or without re-transmission of unacknowledged TCP SA packets. 
def test_servers(servers):
	new_servers = list()
	tds = list()
	sip = "45.125.236.166"
	with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
		futures = []
		for server in servers:
			futures.append(executor.submit(compute_tds, sip, server))
		for future in concurrent.futures.as_completed(futures):
			td, server = future.result()
			if td == 0.0: continue
			tds.append(td)
			new_servers.append(server)
	return new_servers, tds

def ip_spoof_via_ipids(cu, ifile, dataset, ofile):
	gclients = load_vantage_points(cu, ifile)
	for gc in gclients:
		asn = gc[0]
		clients = gc[1]
		random.shuffle(clients)
		if len(clients) > 5000: 
			clients = clients[0:5000]
		clients = test_clients(clients, 'ipid')
		if len(clients) < 0: continue
		start_ipid_ip_spoof(clients, dataset, ofile, cu, asn)
		
def censor_measure_via_ipids(cu, ifile, servers, dataset, ofile):
	servers, tds = test_servers(servers)
	gclients = load_vantage_points(cu, ifile)
	new_gclients = list()
	#we select those ASes that contain at least 50 vantage points and then regarding a specific country we randomly select 10 ASes to meausure for reducing measurement overhead 
	for gc in gclients:
		clients = gc[1]
		if len(clients) < 50: continue
		new_gclients.append(gc)
	rnds = range(len(new_gclients))
	if len(new_gclients) > 10:
		rnds = random.sample(range(0, len(new_gclients)), 10)
	for i in rnds:
		gc = new_gclients[i]
		asn = gc[0]
		clients = gc[1]
		random.shuffle(clients)
		if len(clients) > 10000: 
			clients = clients[0:10000]
		clients = test_clients(clients, 'ipid')
		if len(clients) < 50: continue
		n1 = len(servers)
		n2 = len(clients)
		n = int(n1/n2)
		for i in range(n):
			subclients=clients
			start = i*n2
			end = (i+1) * n2
			subservers = servers[start:end]
			subtds = tds[start:end]
			start_ipid_censor_measure(subclients, subservers, subtds, dataset, ofile, cu, asn)
				
		rest = n1 % n2
		if rest > 0:
			subclients = clients[0:rest]
			subservers = servers[-rest:]
			subtds = tds[-rest:]
			start_ipid_censor_measure(subclients, subservers, subtds, dataset, ofile, cu, asn)
			
def censor_measure(t, measure_type, list_type):
	#lfile = './'+measure_type+'_censor_or_spoof_measure_All.'+list_type+'.{:%Y-%m-%d}.log'.format(datetime.now())
	#set_log_file(lfile)
	dataset1 = {
			'cu': [],
			'asn': [],
			'ip': [],
			'status': [],
		}
	dataset2 = {
			'cu': [],
			'asn': [],
			'ip': [],
			'cls': [],
			'dst_ip': [],
			'status': [],
		}
	'''
	ifile = './test_list_global_All.final.dat'
	global_list = load_global_list(ifile)
	ifile = './test_list_local_All.final.dat'
	local_list=load_local_list(cu, ifile, global_list)
	servers = global_list + local_list
	logging.info('Length of test IP servers for {a} : {b}'.format(a = cu, b= len(servers)))
	'''
	global_list = list()
	ifile = './test_list_global_All.final.dat'
	if measure_type == "ipid":
		print(len(count_unique_ip(ifile, list_type)))
		global_list = load_list_for_ip(ifile, list_type)
	#print('global_list: ', len(global_list))
	for cu in ['RU','TR','IR','IN', 'CN']:
		local_list = list()
		ifile = './test_list_local_All.final.dat' #test_list_local_All.new.dat
		local_list = load_local_list(cu, ifile, measure_type)
		print(len(count_local_ip(cu, ifile, measure_type)))
		#print(cu, len(local_list))
		servers = global_list + local_list
		'''
		if measure_type == 'ipid':
			ifile = './ipid_reflectors_All.asn.dat'
			ofile1 = open('./'+measure_type+'_ip_spoof_'+cu+'.'+t+'.res', 'w')
			ip_spoof_via_ipids(cu, ifile, dataset1, ofile1)
			ofile2 = open('./'+measure_type+'_censor_measure_'+cu+'.'+list_type+'.'+t+'.res', 'w')
			censor_measure_via_ipids(cu, ifile, servers, dataset2, ofile2)
			ofile1.close()
			ofile2.close()
		'''
	
	#df = pd.DataFrame(dataset1)
	#df.to_csv('./ipid_censor_measure_'+cu+'.res', index=False)
	#df = pd.DataFrame(dataset2)
	#df.to_csv('./ratelimit_censor_measure_'+cu+'.res', index=False)

def main():
	parser = argparse.ArgumentParser()
	#parser.add_argument('-cu','--country', type = str, required=True)
	parser.add_argument('-mt','--measure_type', type = str, default= 'ipid', required=True)
	parser.add_argument('-lt','--list_type', type = str, default = 'website', required=True)
	args = parser.parse_args()
	today = date.today()
	d = today.strftime("%Y-%m-%d")
	mt = args.measure_type
	lt = args.list_type
	censor_measure(d, mt, lt) #args.country

if __name__ == "__main__":
    # execute only if run as a script
    main()
