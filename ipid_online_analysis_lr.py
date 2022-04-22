#!/usr/bin/env python3
from numpy import array, asarray
import numpy as np
from ipid_prediction_lib import *
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
import csv
import logging
from sklearn import linear_model
import features_extraction_lib
import warnings
warnings.filterwarnings("ignore")

class go_string(Structure):
    _fields_ = [
        ("p", c_char_p),
        ("n", c_int)]
        

def extract(string_arr):
	arr = []
	matches = re.findall(regex, string_arr)
	for match in matches:
		arr.append(int(match))
	return arr

def modify(times):
	start = times[0]
	i = 0
	for time in times:
		times[i] = int(round(float(time - start)/1000000.0))
		i+=1
	return times

def computeIpidVelocity(ids, times, MAX):

	spd = float(0)

	for i in range(0, len(ids)-1):
		
		gap = float(rela_diff(ids[i], ids[i+1], MAX))
		#dur = float(times[i+1]-times[i])/1000000000.0 #unit: ID/s
		dur = float(times[i+1]-times[i])
		spd += gap/dur
	
	spd /= float(len(ids)-1)
	
	return round(spd, 3)

def computeIpidVelocity02(ids, times, MAX):
	id_seg = list()
	time_seg = list()
	vels = list()
	for i in range(len(ids)):
		id_seg.append(ids[i])
		time_seg.append(times[i])
		if len(id_seg) == 3:
			vel = computeIpidVelocity(id_seg, time_seg, MAX)
			vels.append(vel)
			id_seg = []
			time_seg = []
	return np.median(vels)

def computeIpidVelocitySeg(ids, times, MAX):
	id_segment = []
	time_segment = []
	vels = []
	for i in range(len(ids)):
		if math.isnan(ids[i]):
			if len(id_segment) >= 3:
				vel = computeIpidVelocity(id_segment, time_segment, MAX)
				vels.append(vel)
			id_segment = []
			time_segment = []
			continue
		id_segment.append(ids[i])
		time_segment.append(times[i])
	if len(id_segment) >= 3: # without NAN
		vel = computeIpidVelocity(id_segment, time_segment, MAX)
		vels.append(vel)
	if len(vels) == 2 and len(id_segment) > len(ids)/2: return vels[1]
	return np.median(vels)

def computeIpidVelocityNan(ids, times, MAX):
	id_segment = []
	time_segment = []
	for i in range(len(ids)):
		if math.isnan(ids[i]):
			continue
		id_segment.append(ids[i])
		time_segment.append(times[i])
	vel = computeIpidVelocity(id_segment, time_segment, MAX)
	return vel

def count_ipid_wraps(data):
	count = 0
	for i in range(0, len(data)-1):
		if data[i+1]-data[i] < 0:
			count = count + 1
	return count

def series_to_supervised(data, n_in=1, n_out=1, dropnan=True):
	n_vars = 1 if type(data) is list else data.shape[1]
	df = DataFrame(data)
	cols = list()
	# input sequence (t-n, ... t-1)
	for i in range(n_in, 0, -1):
		cols.append(df.shift(i))
	
	# forecast sequence (t, t+1, ... t+n)
	for i in range(0, n_out):
		cols.append(df.shift(-i))
	
	# put it all together
	agg = concat(cols, axis=1)
	#print(agg)
	# drop rows with NaN values
	if dropnan:
		agg.dropna(inplace=True)
	return agg.values
	
def obtain_restore_data(sequence, diff_data):
	base_data = list()
	restore_data = list()
	for i in range(3, len(diff_data)):
		if math.isnan(diff_data[i-3]+diff_data[i-2]+diff_data[i-1]+diff_data[i]): continue
		base_data.append(sequence[i])
		restore_data.append(sequence[i+1])
	return base_data, restore_data
 
# split a univariate dataset into train/test sets
def train_test_split(data, n_test):
	return data[:-n_test, :], data[-n_test:, :]

# split a univariate sequence into samples
def split_sequence(sequence, n_steps):
	X, y = list(), list()
	for i in range(len(sequence)-n_steps):
		# find the end of this pattern
		end_ix = i + n_steps
		# gather input and output parts of the pattern
		seq_x, seq_y = sequence[i:end_ix], sequence[end_ix]
		X.append(seq_x)
		y.append(seq_y)
	return array(X), array(y)
	
def sMAPE02(chps_ind, actual, predictions):
	res = list()
	for i in range(len(actual)):
		if i in chps_ind and abs(predictions[i]-actual[i]) > 30000:
			if predictions[i] < actual[i]:
				predictions[i] = predictions[i] + 65536
				#res.append(2 * abs(pre-actual[i]) / (actual[i] + pre))
			else:
				actual[i] = actual[i] + 65536
				#res.append(2 * abs(predictions[i]-ac) / (ac + predictions[i]))
			continue
		if  (actual[i] + predictions[i]) !=0:
			if (actual[i] + predictions[i]) <0: continue
			res.append(2 * abs(predictions[i]-actual[i]) / (actual[i] + predictions[i]))
		else:
			res.append(0)
	after_res = list()
	for v in res:
		if math.isnan(v): continue
		after_res.append(v)
	return np.mean(after_res)

def MAPE(chps_ind, actual, predictions):
	res = list()
	for i in range(len(actual)):
		if i in chps_ind and abs(predictions[i]-actual[i]) > 30000:
			if predictions[i] < actual[i]:
				pre = predictions[i] + 65536
				res.append(abs(pre-actual[i]) / actual[i])
			else:
				ac = actual[i] + 65536
				res.append(abs(predictions[i]-ac) / ac )
			continue
		if  (actual[i] + predictions[i]) !=0:
			if (actual[i] + predictions[i]) <0: continue
			res.append(abs(predictions[i]-actual[i]) / actual[i])
		else:
			res.append(0)
	after_res = list()
	for v in res:
		if math.isnan(v): continue
		after_res.append(v)
	return np.mean(after_res)
	
def filter_outliers01(outlier, sequence, thr, MAX):
	indices = list()
	new_window = [i for i in sequence]
	if not outlier: return new_window
	index = 0
	for i in range(index, len(new_window)-2):
		mini_window = [new_window[i], new_window[i+1], new_window[i+2]]
		if containNAN(mini_window): continue
		delta1 = rela_diff(new_window[i], new_window[i+1], MAX)
		delta2 =  rela_diff(new_window[i+1], new_window[i+2], MAX)
		
		if delta1 > thr or delta2 > thr: # suitable for two consecutive outliers
			mini_window = array(mini_window)
			med = np.median(mini_window)
			mini_window = abs(mini_window - med)
			max_index = max( (v, i) for i, v in enumerate(mini_window) )[1]
			if i+max_index == 0: # process the outliers detected
				new_window[i+max_index]  = new_window[1]
			else:
				new_window[i+max_index] = new_window[i+max_index-1]
			indices.append(i+max_index)
			if len(indices) >= 3: ## if the number of consecutive outliers is more than three, then the change will be viewed as normal
				if indices[-2]-indices[-3] == 1 and indices[-1]-indices[-2] == 1:
					new_window = [i for i in sequence]
					index = indices[-1] + 1
	return new_window

def filter_outliersv2(outlier, sequence, thr, MAX, actual, outlier_ind):
	change = False
	new_window = [i for i in sequence]
	if not outlier: return new_window, change
	if len(actual) == len(new_window):
		n = 0
	else:
		n = len(new_window)-3
	for i in range(n, len(new_window)-2):
		mini_window = [new_window[i], new_window[i+1], new_window[i+2]]
		if containNAN(mini_window): continue
		if alarm_turning_point(thr, mini_window[0], mini_window[1], MAX):
			mini_window[1] = (mini_window[1] + MAX) 
		if alarm_turning_point(thr, mini_window[1], mini_window[2], MAX):
			mini_window[2] = (mini_window[2] + MAX) 
		delta1 = rela_diff(mini_window[0], mini_window[1], MAX)
		delta2 =  rela_diff(mini_window[1], mini_window[2], MAX)
		if delta1 > thr or delta2 > thr: # suitable for two consecutive outliers
			mini_window = array(mini_window)
			med = np.median(mini_window)
			mini_window = abs(mini_window - med)
			max_index = max( (v, i) for i, v in enumerate(mini_window) )[1]
			
			if i+max_index == 0: # process the outliers detected
				new_window[i+max_index]  = new_window[1]
			else:
				new_window[i+max_index] = new_window[i+max_index-1]
			outlier_ind.append(len(actual)-len(new_window)+i+max_index)
			if len(outlier_ind) >= 3:	
				if (outlier_ind[-1] - outlier_ind[-2]) == 1 and (outlier_ind[-2] - outlier_ind[-3]) == 1 :
						new_window[i] = actual[i+len(actual)-len(new_window)]
						new_window[i+1] = actual[i+1+len(actual)-len(new_window)]
						new_window[i+2] = actual[i+2+len(actual)-len(new_window)]
						outlier_ind.clear()
						change = True
	return new_window, change
	
	
def alarm_turning_point(thr, a1, a2, MAX):
	alarm = False
	delta = a2 - a1 
	if delta < 0 and rela_diff(a1, a2, MAX) < thr: # a2-a1+MAX approximates to a2 (close to 1 in ideal)
		alarm = True
	return alarm
	

def eliminate_trans_error(chps_ind, actual, predictions):
	diff = list()
	for i in range(len(actual)):
		if i in chps_ind and abs(predictions[i]-actual[i]) > 30000: # if the turning point is predicted with a prior second, then the main prediction error is on the upper turining point, otherwise, th error is on the lower turning point.
			if predictions[i] < actual[i]:
				diff.append(predictions[i]-actual[i] + 65536)
			else:
				diff.append(predictions[i]-actual[i] - 65536)
			continue
		diff.append(predictions[i]-actual[i])
	return diff

def containNAN(data):
	for i in range(len(data)):
		if math.isnan(data[i]): return True
	return False

def countNans(data):
	num = 0
	for i in range(len(data)-2):
		if math.isnan(data[i]):
			if math.isnan(data[i+1]) and math.isnan(data[i+2]):
				num = 3
				return num
	return num
	

def filter_outliers(outliers, thr, history, MAX):
	data = filter_outliers01(outliers, history, thr, MAX)
	return data

def data_preprocess(thr, history, MAX):
	data = [i for i in history]
	wraps = list()
	for i in range(len(data)-1):
		if data[i+1] - data[i] < 0 and rela_diff(data[i], data[i+1], MAX) < thr:
			wraps.append(i+1)
	for _, i in enumerate(wraps):
		for t in range(i, len(data)):
			data[t] = data[t] + MAX
	return wraps, data
		
def one_time_forecast(data, times, ntime, k, predictions, MAX):
	X = np.array(times).reshape(-1, 1)
	y = np.array(data)
	model = linear_model.LinearRegression().fit(X, y)
	nt = np.array(ntime).reshape(-1, 1)
	y_pred = model.predict(nt)[0] - MAX*k
	predictions.append(y_pred)


def ipid_pred(cu, pfx, ip, protocol, flag, port, fs, sl):
	label = predict_ipids(ip, protocol, flag, port, '', fs, sl)
	return cu, pfx, ip, label

def group_ips_measure(ips, protocol, flag, port, domains, fs, sl):
	targets = {}
	for ip, ns in zip(ips, domains):
		code, pred = single_ip_forecast(ip, protocol, flag, port, ns, fs, sl)
		if code == 0:
			targets[ip] = pred
		if len(targets) > 5: 
			return targets
	return targets


def predict_ipids(ipv4, protocol, flag, port, ns, fs, sl):
	ipv4 = bytes(ipv4, 'utf-8')
	protocol = bytes(protocol, 'utf-8')
	ns = bytes(ns, 'utf-8')
	ip = go_string(c_char_p(ipv4), len(ipv4))
	proto = go_string(c_char_p(protocol), len(protocol))
	ns = go_string(c_char_p(ns), len(ns))
	lib.testIP.restype = np.ctypeslib.ndpointer(dtype = int, shape = (sl+1,))
	ids = lib.testIP(ip, proto, port, ns, fs, sl)
	if ids[-1] == 1: 
		#logging.info('Not applicable: {a}'.format(a= ip))
		return 9
	clf = 'svm'
	times = list()
	res = features_extraction_lib.feature_extraction(fs, ids[:-1], times, clf)
	return res
		
def probe(ipv4, protocol, flag, port, ns):
	ipv4 = bytes(ipv4, 'utf-8')
	protocol = bytes(protocol, 'utf-8')
	flag = bytes(flag, 'utf-8')
	ns = bytes(ns, 'utf-8')
	ip = go_string(c_char_p(ipv4), len(ipv4))
	proto = go_string(c_char_p(protocol), len(protocol))
	flag = go_string(c_char_p(flag), len(flag))
	ns = go_string(c_char_p(ns), len(ns))
	a = lib.probe(ip, proto, flag, port, ns)
	return a


def single_ip_forecast(ip, protocol, flag, port, ns, fs, sl):
	code = 0
	pred = None
	count = 0
	for i in range(2):
		ipid = probe(ip, protocol, flag, port, ns)
		if ipid == -1: count = count+1
		time.sleep(1)
	if count == 2:
		#logging.info('Unreachable: {a}'.format(a= ip))
		code = 1
		return code, pred
	
	res = predict_ipids(ip, protocol, flag, port, ns, fs, sl)
	if res != 1:
		#logging.info('Not applicable: {a}, {res}'.format(a= ip, res=res))
		#f.write(ip+','+str(res)+'\n')
		code = 1
		return code, pred
	
	sliding_window = list()
	wlth = 5
	#plth = 100 #this is set for online measurement
	plth = 30
	ipids = list()
	actual = list()
	predictions = list() 
	chps_ind = list()
	outlier_ind = list()
	tem_actual = list()

	while True:
		
		ipid = probe(ip, protocol, flag, port, ns)
		start = time.monotonic()
		ipids.append(ipid)	
		if ipid == -1: ipid = math.nan
		sliding_window.append(ipid)
		tem_actual.append(ipid)
		if len(sliding_window) == wlth+1: 
			actual.append(sliding_window[-1])
			sliding_window.pop(0)
		
		if len(sliding_window) == wlth:
			count = 0
			for x in sliding_window:
				if math.isnan(x): count = count + 1
			if count/wlth > 0.5:
				predictions.append(math.nan)
				end = time.monotonic()
				elapsed = end-start
				#lambda elapsed:  time.sleep(1-elapsed) if elapsed < 1 else time.sleep(0)
				time.sleep(1)
				continue
			times = list()
			for i in range(len(sliding_window)):
				times.append(i)
			tHistory = times
			MAX = 65536
			
			outlier = True
			
			if containNAN(sliding_window):
				vel = computeIpidVelocityNan(sliding_window, list(range(len(sliding_window))), MAX)
			else:
				vel = computeIpidVelocity02(sliding_window, list(range(len(sliding_window))), MAX) # eliminate the outliers' impact
			
			if vel < 1000: thr = 15000 # experimentially specify the threshold
			else: thr = 30000
			if vel > 10000: outlier = False # For high fluctuating
			
			if len(predictions) > 1  and  alarm_turning_point(thr, tem_actual[-2], tem_actual[-1], MAX):
					chps_ind.append(i-2)
					chps_ind.append(i-1)
			if len(predictions) == plth: break	
			sliding_window = fill_miss_values(sliding_window) 
			
			sliding_window, _ = filter_outliersv2(outlier, sliding_window, thr, MAX, tem_actual, outlier_ind)
			
			wraps, new_window = data_preprocess(thr, sliding_window, MAX) # identify the truning point and make a preprocessing
			k = len(wraps)
			ntime = tHistory[-1]+1
			one_time_forecast(new_window, tHistory, ntime, k, predictions, MAX)
			if predictions[-1] < 0: predictions[-1] = 0
			
		end = time.monotonic()
		elapsed = end-start
		time.sleep(1)
		
	after_predictions = list()
	for v in predictions:
		if math.isnan(v): 
			after_predictions.append(v)
		else:
			after_predictions.append(round(v))
	predictions = after_predictions
	
	diff = eliminate_trans_error(chps_ind, actual, predictions)
	after_diff = list()
	for v in diff:
		if math.isnan(v): continue
		after_diff.append(v)
	
	if len(after_diff) < plth * 0.7:
		#logging.info('Invalid: {a}'.format(a= ip))
		code = 1
		return code, pred
		
	mae = np.mean(abs(array(after_diff)))
	smape = sMAPE02(chps_ind, actual, predictions)
	pred = 1-smape
	#logging.info('{a} | {b} | {c} | {d} | {e} | {f}'.format(a= ip, b = ipids, c = actual, d = predictions, e = mae, f = smape))
	return code, pred
	
def fill_miss_values(data):
	s = pd.Series(data)
	s = s.interpolate(method='pad')
	return (s.interpolate(method='linear', limit_direction ='both').values % 65536).tolist()

def filter_data():
	ips = list()
	f = open('../ipid_prediction/Dataset/online_analysis/routers_global.data.new.res', 'w')
	with open('../ipid_prediction/Dataset/online_analysis/routers_global.data.res', 'r') as filehandle:
		filecontents = filehandle.readlines()
		for line in filecontents:
			fields = line.split(",")
			if len(fields) < 3 : continue
			ip = fields[0]
			if ip in ips: continue
			ips.append(ip)
			f.write(line)
	f.close()
	


def online_analysis_res():
	ips = list()
	with open('../ipid_prediction/evaluate/online_analysis/nameservers.non_global_ipids.res', 'r') as filehandle:
		filecontents = filehandle.readlines()
		for line in filecontents:
			fields = line.split(",")
			if len(fields) < 1 : continue
			ip = fields[0]
			ips.append(ip)
			
	
	res = {}
	for i in range(1,4):
		with open('../ipid_prediction/evaluate/online_analysis/lr.nameservers.0'+str(i)+'.log') as filehandle:
			filecontents = filehandle.readlines()
			for line in filecontents:
				fields = line.split("|")
				if len(fields) < 5 : continue
				ip = fields[0].split(':')[-1].strip(' ')
				if ip in ips: continue
				mae = float(fields[-2].strip(' '))
				smape = float(fields[-1].strip(' '))
			
				if ip in res: 
					res[ip]['maes'].append(mae)
					res[ip]['smapes'].append(smape)
				else:
					res[ip] = dict({
						'maes': [mae],
						'smapes': [smape]
						})
				
	f = open('../ipid_prediction/evaluate/online_analysis/lr.nameservers.predictability.res', 'w')
	#f0 = open('../ipid_prediction/evaluate/online_analysis/lr.reflectors.(low).res', 'w')
	for ip in res:
		mae = np.mean(np.array(res[ip]['maes']))
		smape = np.mean(np.array(res[ip]['smapes']))
		#if smape < 0.001: 
			#f0.write(ip+'\n')
		f.write(ip+','+str(mae)+','+str(smape)+'\n')
	f.close()
	#f0.close()

lib = cdll.LoadLibrary("./ipid_pred_lib.so")
#logging.basicConfig(level=logging.INFO, filename='./lr.test.log')
#f = open('./routers.non_global_ipids.res', 'w')
def main():
	#lr()
	#single_ip_forecast('218.223.90.225', 'tcp', 'SA', 80, '', 1, 20)
	#test()
	#f.close()
	#online_analysis_res()
	#filter_data()
	split()

def split():
	f1 = open('../training_data/new_data/perConn.part1.data', 'w')
	f2 = open('../training_data/new_data/perConn.part2.data', 'w')
	with open('../training_data/new_data/perConn.data', 'r') as filehandle:	
		filecontents = filehandle.readlines()
		i = 0
		for line in filecontents:
			fields = line.split(",")
			if len(fields) < 1 : continue
			if i >= 5000:
				f2.write(line)
			else:
				f1.write(line)
			i = i + 1
	f1.close()
	f2.close()
			
def test():
	mutex=threading.Lock()
	ips_list = list()
	domains_list = list()
	ips = list()
	domains = list()
	#with open('../ipid_prediction/Dataset/online_analysis/nameservers_global.data.res', 'r') as filehandle:
	with open('./routers_global.data.res', 'r') as filehandle:	
		filecontents = filehandle.readlines()
		for line in filecontents:
			fields = line.split(",")
			if len(fields) < 1 : continue
			#domain = fields[1]
			domain = ''
			ip = fields[0] 
			domains.append(domain)
			ips.append(ip)
			if len(ips) == 10: #10
				ips_list.append(ips)
				domains_list.append(domains)
				ips = list()
				domains = list()
	ips_list.append(ips)
	domains_list.append(domains)
	print(len(ips_list))
	protocol = 'icmp'
	port = 0
	flag = ' '
	fs = 2
	sl = 60
	with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
		futures = []
		for ips, domains in zip(ips_list, domains_list):
			futures.append(executor.submit(group_ips_measure, ips, protocol, flag, port, domains, fs, sl))
		for future in concurrent.futures.as_completed(futures):
			print('Done!')
			
if __name__ == "__main__":
    # execute only if run as a script
    main()


