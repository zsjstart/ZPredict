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
from scipy.optimize import fsolve
from sklearn.gaussian_process import GaussianProcessRegressor
from sklearn.gaussian_process.kernels import RBF, DotProduct, WhiteKernel, ConstantKernel as C
import warnings
import re
import glob
import os
from parse_pcap import *
from ipwhois import IPWhois
from ipid_online_analysis_lr import predict_ipids
 
warnings.filterwarnings("ignore")

#import seaborn as sns
#import matplotlib.pyplot as plt

#cols = sns.color_palette("colorblind")
#sns.set_theme(style="darkgrid")

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


def group_ips_measure(ips, protocol, port, domains, dst_ip, dst_port, td, l, spoof, dataset):
	for ip, ns in zip(ips, domains):
		controlled_experiment(ip, protocol, port, ns, dst_ip, dst_port, td, l, spoof, dataset)
		
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
		
def spoofing_probe(ipv4, protocol, port, ns, dst_ip, dst_port, n, flag):
	ipv4 = bytes(ipv4, 'utf-8')
	protocol = bytes(protocol, 'utf-8')
	ns = bytes(ns, 'utf-8')
	dst_ip = bytes(dst_ip, 'utf-8')
	flag = bytes(flag, 'utf-8')
	
	ip = go_string(c_char_p(ipv4), len(ipv4))
	proto = go_string(c_char_p(protocol), len(protocol))
	ns = go_string(c_char_p(ns), len(ns))
	dst_ip = go_string(c_char_p(dst_ip), len(dst_ip))
	flag = go_string(c_char_p(flag), len(flag))
	lib.spoofing_probe(ip, dst_ip, proto, port, dst_port, ns, n, flag) #port: reflector port

def spoofing_samples(diff_data):
	e = np.max(diff_data, axis=-1) #when the estimated error is the maximum of previous errors, maybe an abnormal value when there is ana outlier
	u = np.mean(diff_data)
	s = np.std(diff_data)
	#if s == 0: # to keep the trend monotonously increasing
	#	n = 5
	#else:
	n = 1+int(4*s+e-u) # > 1.64 when p = 0.05, 2.06 when p = 0.02
	# next, set p2
	'''n2 = 2*n
	y2 = round(fsolve(func, 2.1, xtol=10.**-20, args=(n2, e, u, s))[0], 4)
	p2 = norm.cdf(-y2)'''
	return n, u, s, e

def func(x, *args):
        try:
            n, e, u, s = args
            return 1+int(x*s+e-u) - n
        except Exception as err:
            logging.error(err)
            return None
	
	
	
def is_open_port(u, s, e, n):
	if s == 0:
		if abs(e) >= n: return True
		else: return False
	
	v = (e-u)/s
	if norm.cdf(v) > 0.98 or norm.cdf(v) < 0.02: # p = 0.02
		return True
	return False

def detect01(err, p, u, s, n):
	status1 = 'abnormal'
	status2 = 'normal'
	status3 = 'undetectable'
	if math.isnan(err): return status3
	if s == 0:
		if abs(err) >= n: return status1
		else: return status2
	
	v = (err-u)/s
	if norm.cdf(v) >= 1-p or norm.cdf(v) <= p: # p = 0.02
		return status1
	return status2

def detect02(errs, p, u, s, n):
	status1 = 'no blocked'
	status2 = 'outbound blocking'
	status3 = 'undetectable'
	for err in errs:
		if math.isnan(err): return status3
	res = list()
	for err in errs:
		res.append(detect01(err, p, u, s, n))
	c = 0
	for r in res:
		if r == 'abnormal':
			c = c+1
	if c >= 1: # at least one
		return status2
	return status1
		
		
	
def detect_new(err1, p, err2, u, s, n):
	status1 = 'inbound blocking'
	status2 = 'no blocked'
	status3 = 'outbound blocking'
	status4 = 'undetectable'
	'''if s == 0:
		if abs(err1) < n: #abs(err4) < n
			return status1
		elif n <= abs(err1)  and abs(err4) < n: # abs(err1) < 2*n
			return status2
		elif n <= abs(err1)  and abs(err4) >= n:
			return status3
		else:
			return status4
	
	p_e1 = norm.cdf((err1-u)/s)
	p_e4 = norm.cdf((err4-u)/s)
	if p_e1 > p: #p_e4 > p1
		return status1
	elif p_e1 <= p and p_e4 > p: # p2 < p_e1 <= p1
		return status2
	elif p_e1 <= p and p_e4 <= p: #  p2 < p_e1 <= p1
		return status3
	else:
		return status4'''
	st1 = detect01(err1, p, u, s, n)
	st2 = detect01(err2, p, u, s, n)
	if st1 == 'normal':
		return status1
	elif st1 == 'abnormal' and st2 == 'normal':
		return status2
	elif st1 == 'abnormal' and st2 == 'abnormal':
		return status3
	else:
		return status4
	
	

def test_dst_port(ip, protocol, flag, port, ns):
	count = 0
	status = 'open'
	for i in range(2):
		ipid = probe(ip, protocol, flag, port, ns)
		if ipid == -1: count = count+1
		time.sleep(1)
	if count == 2:
		status = 'closed'
	return status, ip
	
def pre_processing(sequence, MAX):
	diff_data = difference(sequence, 1, MAX)
	diff_data = array(diff_data).reshape(-1, 1)
	scaler = preprocessing.MinMaxScaler()
	diff_data = scaler.fit_transform(diff_data) # scaling the input and output data to the range of (0,1)
	minimum = scaler.data_min_
	maximum = scaler.data_max_
	return diff_data, maximum, minimum

def gp_one_time_forecast(sequence, predictions, MAX):
	diff_data, maximum, minimum = pre_processing(sequence, MAX)
	X = np.array(range(len(sequence)-1)).reshape(-1, 1) # for time
	y = np.array(diff_data)
	#kernel = DotProduct() + WhiteKernel()
	#kernel = C(constant_value=10, constant_value_bounds=(1e-2, 1e3))*RBF(length_scale=1e2, length_scale_bounds=(1, 1e3)) Not suitable!!!
	#kernel = DotProduct() #this kernel cannot deal witht the abrupt changes or outliers (i.g., noise), but is well-suited for the linear changes
	#kernel = DotProduct()
	kernel =  WhiteKernel() 
	#kernel = WhiteKernel() #noise_level=0.3**2, noise_level_bounds=(0.1**2, 0.5**2)
	warnings.filterwarnings("ignore")
	gp = GaussianProcessRegressor(kernel=kernel, n_restarts_optimizer=5)
	gp.fit(X, y)
	nt = np.array(len(sequence)).reshape(-1, 1)
	y_pred, sigma = gp.predict(nt, return_std=True)
	y_pred = denormalize(y_pred, maximum, minimum)
	prediction = (y_pred[0] + sequence[-1])%MAX
	predictions.append(prediction[0])
	
def single_port_scan_old(ip, protocol, port, ns, dst_ip, dst_port, plth, spoof, dataset):
	code = 0
	count = 0
	for i in range(2):
		ipid = probe(ip, protocol, 'SA', port, ns)
		if ipid == -1: count = count+1
	if count == 2:
		logging.info('Unreachable: {a}'.format(a= ip))
		code = 1
		return code, dst_ip
	
	#astatus = test_dst_port(dst_ip, protocol, 'S', dst_port, ns)
	astatus = ''
	'''if astatus == 'open': ##need to be updated when no open
		logging.info('Open: {a}'.format(a= dst_ip))
		code = 1
		return code, dst_ip'''
	
	sliding_window = list()
	wlth = 5
	#plth = 30
	ipids = list()
	actual = list()
	predictions = list() 
	chps_ind = list()
	outlier_ind = list()
	tem_actual = list()
	mae, smape, n, u, s = 0.0, 0.0, 0, 0.0, 0.0
	emax = 0.0
	p2 = 0.02
	while True:
		ipid = probe(ip, protocol, 'SA', port, ns)
		start = time.monotonic()
		ipids.append(ipid)	
		if ipid == -1: ipid = math.nan
		if len(predictions) >= plth:
			sliding_window.append(predictions[-1]-u) 
		else:
			sliding_window.append(ipid)
		tem_actual.append(ipid)
		if len(sliding_window) == wlth+1: 
			actual.append(ipid)
			sliding_window.pop(0)
		if len(predictions) == plth-1:
			diff = eliminate_trans_error(chps_ind, actual, predictions)
			after_diff = list()
			for v in diff:
				if math.isnan(v): continue
				after_diff.append(v)
			
			if len(after_diff) < (plth-1) * 0.7:
				logging.info('Invalid: {a}'.format(a= ip))
				code = 1
				return code, dst_ip
			mae = np.mean(abs(array(after_diff)))
			smape = sMAPE02(chps_ind, actual, predictions)
			n, u, s, emax = spoofing_samples(after_diff)
			#print('n, p2: ', n, p2)
			#f.write(ip+','+str(smape)+','+str(n)+'\n')
			if n > 10:
				logging.info('n>10, require retest: {a}'.format(a= ip)) # 10
				code = 1
				return code, dst_ip
			if spoof:
				spoofing_probe(ip, protocol, port, ns, dst_ip, dst_port, n) # port should be random
				#spoofing_probe(dst_ip, protocol, dst_port, ns, ip, port, n) #test_pred_n, port should be random
				
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
			if len(predictions) >= plth: outlier = False
			
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
					
			if len(predictions) == plth + 3: break # Update!!!
			
			sliding_window = fill_miss_values(sliding_window) 
			
			sliding_window, _ = filter_outliersv2(outlier, sliding_window, thr, MAX, tem_actual, outlier_ind)
			
			wraps, new_window = data_preprocess(thr, sliding_window, MAX) # identify the truning point and make a preprocessing
			k = len(wraps)
			ntime = tHistory[-1]+1
			one_time_forecast(new_window, tHistory, ntime, k, predictions, MAX)
			if predictions[-1] < 0: predictions[-1] = 0
			
		end = time.monotonic()
		elapsed = end-start
		#lambda elapsed:  time.sleep(1-elapsed) if elapsed < 1 else time.sleep(0)
		time.sleep(1)
	diff = eliminate_trans_error(chps_ind, actual, predictions)
	if math.isnan(diff[-1]) or math.isnan(diff[-4]):
		logging.info('Packet loss: {a}'.format(a= ip))
		code = 1
		return code, dst_ip
	# here design a test: no error, manually subtract n or 2*n to the predcition errors
	err1 = diff[-4] - n
	p1 = 0.02
	err4 = diff[-1] - n
	status = None
	status = detect(err1, p1, err4, p2, u, s, n)
	print('status: ', status, n)
	
	dataset['ip'].append(ip)
	dataset['mae'].append(mae)
	dataset['smape'].append(smape)
	dataset['n'].append(n)
	dataset['status'].append(status)
	dataset['dst_ip'].append(dst_ip)
	dataset['astatus'].append(astatus)
	#print(ip, dst_ip, status, astatus)
	logging.info('{a} | {b} | {c} | {d}'.format(a= ip, b = dst_ip, c = actual, d = predictions))
	return code, dst_ip

def single_port_scan_v2(ip, protocol, port, ns, dst_ip, dst_port, plth, spoof, dataset):
	code = 0
	count = 0
	for i in range(2):
		ipid = probe(ip, protocol, 'SA', port, ns)
		if ipid == -1: count = count+1
	if count == 2:
		logging.info('Unreachable: {a}'.format(a= ip))
		code = 1
		return code, dst_ip
	
	#astatus = test_dst_port(dst_ip, protocol, 'S', dst_port, ns)
	astatus = ''
	'''if astatus == 'open': ##need to be updated when no open
		logging.info('Open: {a}'.format(a= dst_ip))
		code = 1
		return code, dst_ip'''
	
	sliding_window = list()
	wlth = 5
	#plth = 30
	ipids = list()
	actual = list()
	predictions = list() 
	chps_ind = list()
	outlier_ind = list()
	tem_actual = list()
	mae, smape, n, u, s = 0.0, 0.0, 0, 0.0, 0.0
	emax = 0.0
	p2 = 0.02
	while True:
		ipid = probe(ip, protocol, 'SA', port, ns)
		start = time.monotonic()
		ipids.append(ipid)	
		if ipid == -1: ipid = math.nan
		if len(predictions) >= plth:
			sliding_window.append(predictions[-1]) 
		else:
			sliding_window.append(ipid)
		tem_actual.append(ipid)
		if len(predictions) < plth:
			if len(sliding_window) == wlth+1: 
				actual.append(ipid)
				sliding_window.pop(0)
		else:
			actual.append(ipid)
		if len(predictions) == plth-1:
			diff = eliminate_trans_error(chps_ind, actual, predictions)
			after_diff = list()
			for v in diff:
				if math.isnan(v): continue
				after_diff.append(v)
			
			if len(after_diff) < (plth-1) * 0.7:
				logging.info('Invalid: {a}'.format(a= ip))
				code = 1
				return code, dst_ip
			mae = np.mean(abs(array(after_diff)))
			smape = sMAPE02(chps_ind, actual, predictions)
			n, u, s, emax = spoofing_samples(after_diff)
			#print('n, p2: ', n, p2)
			#f.write(ip+','+str(smape)+','+str(n)+'\n')
			if n > 10:
				logging.info('n>10, require retest: {a}'.format(a= ip)) # 10
				code = 1
				return code, dst_ip
			if spoof:
				spoofing_probe(ip, protocol, port, ns, dst_ip, dst_port, n) # port should be random
				#spoofing_probe(dst_ip, protocol, dst_port, ns, ip, port, n) #test_pred_n, port should be random
				
		if len(sliding_window) >= wlth:
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
			if len(predictions) >= plth: outlier = False
			
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
					
			if len(predictions) == plth + 3: break # Update!!!
			
			sliding_window = fill_miss_values(sliding_window) 
			
			sliding_window, _ = filter_outliersv2(outlier, sliding_window, thr, MAX, tem_actual, outlier_ind)
			
			gp_one_time_forecast(sliding_window, predictions, MAX)
			if predictions[-1] < 0: predictions[-1] = 0
			
		end = time.monotonic()
		elapsed = end-start
		#lambda elapsed:  time.sleep(1-elapsed) if elapsed < 1 else time.sleep(0)
		time.sleep(1)
	diff = eliminate_trans_error(chps_ind, actual, predictions)
	if math.isnan(diff[-1]) or math.isnan(diff[-4]):
		logging.info('Packet loss: {a}'.format(a= ip))
		code = 1
		return code, dst_ip
	# here design a test: no error, manually subtract n or 2*n to the predcition errors
	err1 = diff[-4] - n
	p1 = 0.02
	err4 = diff[-1] - n
	status = None
	status = detect(err1, p1, err4, p2, u, s, n)
	print('status: ', status, n)
	#print('actual: ', actual)
	#print('predictions: ', predictions)
	
	dataset['ip'].append(ip)
	dataset['mae'].append(mae)
	dataset['smape'].append(smape)
	dataset['n'].append(n)
	dataset['status'].append(status)
	dataset['dst_ip'].append(dst_ip)
	dataset['astatus'].append(astatus)
	#print(ip, dst_ip, status, astatus)
	logging.info('{a} | {b} | {c} | {d}'.format(a= ip, b = dst_ip, c = actual, d = predictions))
	return code, dst_ip

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

def controlled_experiment(ip, protocol, port, ns, dst_ip, dst_port, td, plth, spoof, dataset):
	code = 0
	count = 0
	for i in range(3):
		ipid = probe(ip, protocol, 'SA', port, ns)
		if ipid == -1: count = count+1
		time.sleep(1)
	if count == 3:
		logging.info('Client unreachable: {a}'.format(a= ip))
		code = 1
		return code, dst_ip
	
	#Here adding IP ID classification!!!!!!
	res = predict_ipids(ip, protocol,'SA', port, ns, 1, 10) # fs = 1, sl = 10
	if res != 1:
		logging.info('Not applicable client: {a}, {res}'.format(a= ip, res=res))
		code = 1
		return code, dst_ip
	
	sliding_window = list()
	pr = 1
	wlth = 5
	plth = plth 
	mae, smape, n, u, s = 0.0, 0.0, 0, 0.0, 0.0
	emax = 0.0
	p2 = 0.02
	flag = 'control'
	ipids = list()
	actual = list()
	predictions = list() 
	chps_ind = list()
	outlier_ind = list()
	tem_actual = list()
	while True:
		ipid = probe(ip, protocol, 'SA', port, ns)
		start = time.monotonic()
		ipids.append(ipid)	
		if ipid == -1: ipid = math.nan
		sliding_window.append(ipid)
		tem_actual.append(ipid)
		if len(sliding_window) == wlth+1: 
			actual.append(ipid)
			sliding_window.pop(0)
		if len(predictions) == plth-1:
			diff = eliminate_trans_error(chps_ind, actual, predictions)
			after_diff = list()
			for v in diff:
				if math.isnan(v): continue
				after_diff.append(v)
			
			if len(after_diff) < (plth-1) * 0.7:
				logging.info('Invalid: {a}, {b}'.format(a= ip, b = actual))
				code = 1
				return code, dst_ip
			mae = np.mean(abs(array(after_diff)))
			smape = sMAPE02(chps_ind, actual, predictions)
			n, u, s, emax = spoofing_samples(after_diff)
			#print('n, p2: ', n, p2)
			#f.write(ip+','+str(smape)+','+str(n)+'\n')
			if n > 10:
				logging.info('n>10, require retest: {a}'.format(a= ip)) # 10
				code = 1
				return code, dst_ip
			if spoof:
				spoofing_probe(dst_ip, protocol, dst_port, ns, ip, port, n, flag) #test_pred_n, port should be random
		if len(predictions) == plth-1+td:
			if spoof:
				spoofing_probe(dst_ip, protocol, dst_port, ns, ip, port, n, flag) #test_pred_n, port should be random
		if len(sliding_window) == wlth:
			count = 0
			for x in sliding_window:
				if math.isnan(x): count = count + 1
			if count/wlth > 0.5:
				predictions.append(math.nan)
				time.sleep(pr)
				continue
			times = list()
			for i in range(len(sliding_window)):
				times.append(i)
			tHistory = times
			MAX = 65536
			
			outlier = True
			if len(predictions) >= plth: outlier = False
			
			if containNAN(sliding_window):
				vel = computeIpidVelocityNan(sliding_window, list(range(len(sliding_window))), MAX)
			else:
				vel = computeIpidVelocity02(sliding_window, list(range(len(sliding_window))), MAX) # eliminate the outliers' impact
			
			if vel < 1000: thr = 15000 # experimentially specify the threshold
			else: thr = 30000
			if vel > 10000: outlier = False # For high fluctuating
			
			if len(predictions) > 1  and  alarm_turning_point(thr, tem_actual[-2], tem_actual[-1], MAX): # identify the turning points to find IP ID wrapping for data recovery or remove extra prediction errors
					chps_ind.append(i-2)
					chps_ind.append(i-1)
					
			if len(predictions) == plth+td: break 
			
			sliding_window = fill_miss_values(sliding_window) 
			
			sliding_window, _ = filter_outliersv2(outlier, sliding_window, thr, MAX, tem_actual, outlier_ind)
			
			gp_one_time_forecast(sliding_window, predictions, MAX)
			'''wraps, new_window = data_preprocess(thr, sliding_window, MAX) # identify the truning point and make a preprocessing
			k = len(wraps)
			ntime = tHistory[-1]+1
			one_time_forecast(new_window, tHistory, ntime, k, predictions, MAX)'''
			if predictions[-1] < 0: predictions[-1] = 0
			
		#lambda elapsed:  time.sleep(1-elapsed) if elapsed < 1 else time.sleep(0)
		time.sleep(pr)
		#end = time.monotonic()
		#elapsed = end-start
		#print(elapsed)
	diff = eliminate_trans_error(chps_ind, actual, predictions)
	# here design a test: no error, manually subtract n to the predcition errors
	err1 = diff[-(td+1)]
	p = 0.02
	err2 = diff[-1]
	status = None
	status = detect_new(err1, p, err2, u, s, n)
	print('status: ', status, n)
	
	dataset['ip'].append(ip)
	dataset['mae'].append(mae)
	dataset['smape'].append(smape)
	dataset['n'].append(n)
	dataset['status'].append(status)
	dataset['dst_ip'].append(dst_ip)
	#print(ip, dst_ip, status, astatus)
	logging.info('{a} | {b} | {c} | {d}'.format(a= ip, b = dst_ip, c = actual, d = predictions))
	return code, dst_ip

def controlled_experimentV2(ip, protocol, port, ns, dst_ip, dst_port, td, plth, spoof, dataset):
	code = 0		
	count = 0
	for i in range(2):
		ipid = probe(ip, protocol, 'SA', port, ns)
		if ipid == -1: count = count+1
		time.sleep(1)
	if count == 2:
		logging.info('Client unreachable: {a}'.format(a= ip))
		code = 1
		return code, dst_ip
	
	res = predict_ipids(ip, protocol,'SA', port, ns, 1, 10) # fs = 1, sl = 10
	if res != 1:
		logging.info('Not applicable client: {a}, {res}'.format(a= ip, res=res))
		code = 1
		return code, dst_ip
	
	sliding_window = list()
	pr = 1
	wlth = 5
	plth = plth 
	mae, smape, n, u, s = 0.0, 0.0, 0, 0.0, 0.0
	emax = 0.0
	p2 = 0.02
	flag = 'control'
	ipids = list()
	actual = list()
	predictions = list() 
	chps_ind = list()
	outlier_ind = list()
	tem_actual = list()
	while True:
		ipid = probe(ip, protocol, 'SA', port, ns)
		start = time.monotonic()
		ipids.append(ipid)	
		if ipid == -1: ipid = math.nan
		sliding_window.append(ipid)
		tem_actual.append(ipid)
		if len(sliding_window) == wlth+1: 
			actual.append(ipid)
			sliding_window.pop(0)
		if len(predictions) == plth-1:
			diff = eliminate_trans_error(chps_ind, actual, predictions)
			after_diff = list()
			for v in diff:
				if math.isnan(v): continue
				after_diff.append(v)
			
			if len(after_diff) < (plth-1) * 0.7:
				logging.info('Invalid: {a}, {b}'.format(a= ip, b = actual))
				code = 1
				return code, dst_ip
			mae = np.mean(abs(array(after_diff)))
			smape = sMAPE02(chps_ind, actual, predictions)
			n, u, s, emax = spoofing_samples(after_diff)
			#print('n, p2: ', n, p2)
			#f.write(ip+','+str(smape)+','+str(n)+'\n')
			if n > 20 or n<5:
				logging.info('n>20 or n<5, require retest: {a}'.format(a= ip)) # 10
				code = 1
				return code, dst_ip
			if spoof:
				spoofing_probe(dst_ip, protocol, dst_port, ns, ip, port, n, flag) #test_pred_n, port should be random
		'''if len(predictions) == plth-1+td:
			if spoof:
				spoofing_probe(dst_ip, protocol, dst_port, ns, ip, port, n, flag) #test_pred_n, port should be random'''
		if len(sliding_window) == wlth:
			count = 0
			for x in sliding_window:
				if math.isnan(x): count = count + 1
			if count/wlth > 0.5:
				predictions.append(math.nan)
				time.sleep(pr)
				continue
			times = list()
			for i in range(len(sliding_window)):
				times.append(i)
			tHistory = times
			MAX = 65536
			
			outlier = True
			if len(predictions) >= plth: outlier = False
			
			if containNAN(sliding_window):
				vel = computeIpidVelocityNan(sliding_window, list(range(len(sliding_window))), MAX)
			else:
				vel = computeIpidVelocity02(sliding_window, list(range(len(sliding_window))), MAX) # eliminate the outliers' impact
			
			if vel < 1000: thr = 15000 # experimentially specify the threshold
			else: thr = 30000
			if vel > 10000: outlier = False # For high fluctuating
			
			if len(predictions) > 1  and  alarm_turning_point(thr, tem_actual[-2], tem_actual[-1], MAX): # identify the turning points to find IP ID wrapping for data recovery or remove extra prediction errors
					chps_ind.append(i-2)
					chps_ind.append(i-1)
					
			if len(predictions) == plth+5: break 
			
			sliding_window = fill_miss_values(sliding_window) 
			
			sliding_window, _ = filter_outliersv2(outlier, sliding_window, thr, MAX, tem_actual, outlier_ind)
			
			gp_one_time_forecast(sliding_window, predictions, MAX)
			'''wraps, new_window = data_preprocess(thr, sliding_window, MAX) # identify the truning point and make a preprocessing
			k = len(wraps)
			ntime = tHistory[-1]+1
			one_time_forecast(new_window, tHistory, ntime, k, predictions, MAX)'''
			if predictions[-1] < 0: predictions[-1] = 0
			
		#lambda elapsed:  time.sleep(1-elapsed) if elapsed < 1 else time.sleep(0)
		time.sleep(pr)
	diff = eliminate_trans_error(chps_ind, actual, predictions)
	#when error is NAN, then 'undetected'
	err1 = diff[-6] # error at the 30s
	p = 0.02
	status = detect01(err1, p, u, s, n)
	if status == 'normal':
		status = 'inbound blocking'
	if status == 'abnormal':
		errs = diff[-5:]
		status = detect02(errs, p, u, s, n)
	print('status:', status)
	dataset['ip'].append(ip)
	dataset['mae'].append(mae)
	dataset['smape'].append(smape)
	dataset['n'].append(n)
	dataset['status'].append(status)
	dataset['dst_ip'].append(dst_ip)	
	#print(ip, dst_ip, status, astatus)
	logging.info('{a} | {b} | {c} | {d}'.format(a= ip, b = dst_ip, c = actual, d = predictions))
	return code, dst_ip

	
	
def single_port_scan(ip, protocol, port, ns, dst_ip, dst_port, plth, spoof, dataset, cu):
	code = 0		
	count = 0
	for i in range(3):
		ipid = probe(ip, protocol, 'SA', port, ns)
		if ipid == -1: count = count+1
		time.sleep(1)
	if count == 3:
		logging.info('Client unreachable: {a}'.format(a= ip))
		code = 1
		return code, dst_ip
	
	res = predict_ipids(ip, protocol,'SA', port, ns, 1, 10) # fs = 1, sl = 10
	if res != 1:
		logging.info('Not applicable: {a}, {res}'.format(a= ip, res=res))
		code = 1
		return code, dst_ip
	
	#astatus = test_dst_port(dst_ip, protocol, 'S', dst_port, ns)
	td = compute_td(dst_ip, dst_port)
	print(td)
	if td == 0:
		logging.info('Web server unreachable: {a}'.format(a = dst_ip))
		code = 1
		return code, dst_ip
	
	sliding_window = list()
	pr = 1
	wlth = 5
	plth = plth 
	mae, smape, n, u, s = 0.0, 0.0, 0, 0.0, 0.0
	emax = 0.0
	p2 = 0.02
	flag = 'test'
	ipids = list()
	actual = list()
	predictions = list() 
	chps_ind = list()
	outlier_ind = list()
	tem_actual = list()
	while True:
		ipid = probe(ip, protocol, 'SA', port, ns)
		start = time.monotonic()
		ipids.append(ipid)	
		if ipid == -1: ipid = math.nan
		sliding_window.append(ipid)
		tem_actual.append(ipid)
		if len(sliding_window) == wlth+1: 
			actual.append(ipid)
			sliding_window.pop(0)
		if len(predictions) == plth-1:
			diff = eliminate_trans_error(chps_ind, actual, predictions)
			after_diff = list()
			for v in diff:
				if math.isnan(v): continue
				after_diff.append(v)
			
			if len(after_diff) < (plth-1) * 0.7:
				logging.info('Invalid: {a}, {b}'.format(a= ip, b = actual))
				code = 1
				return code, dst_ip
			mae = np.mean(abs(array(after_diff)))
			smape = sMAPE02(chps_ind, actual, predictions)
			n, u, s, emax = spoofing_samples(after_diff)
			#print('n, p2: ', n, p2)
			#f.write(ip+','+str(smape)+','+str(n)+'\n')
			if n > 10:
				logging.info('n>10, require retest: {a}'.format(a= ip)) # 10
				code = 1
				return code, dst_ip
			if spoof:
				spoofing_probe(ip, protocol, port, ns, dst_ip, dst_port, n, flag) # port should be random
				#spoofing_probe(dst_ip, protocol, dst_port, ns, ip, port, n, flag) #test_pred_n, port should be random
		if len(sliding_window) == wlth:
			count = 0
			for x in sliding_window:
				if math.isnan(x): count = count + 1
			if count/wlth > 0.5:
				predictions.append(math.nan)
				time.sleep(pr)
				continue
			times = list()
			for i in range(len(sliding_window)):
				times.append(i)
			tHistory = times
			MAX = 65536
			
			outlier = True
			if len(predictions) >= plth: outlier = False
			
			if containNAN(sliding_window):
				vel = computeIpidVelocityNan(sliding_window, list(range(len(sliding_window))), MAX)
			else:
				vel = computeIpidVelocity02(sliding_window, list(range(len(sliding_window))), MAX) # eliminate the outliers' impact
			
			if vel < 1000: thr = 15000 # experimentially specify the threshold
			else: thr = 30000
			if vel > 10000: outlier = False # For high fluctuating
			
			if len(predictions) > 1  and  alarm_turning_point(thr, tem_actual[-2], tem_actual[-1], MAX): # identify the turning points to find IP ID wrapping for data recovery or remove extra prediction errors
					chps_ind.append(i-2)
					chps_ind.append(i-1)
					
			if len(predictions) == plth+td: break 
			
			sliding_window = fill_miss_values(sliding_window) 
			
			sliding_window, _ = filter_outliersv2(outlier, sliding_window, thr, MAX, tem_actual, outlier_ind)
			
			gp_one_time_forecast(sliding_window, predictions, MAX)
			'''wraps, new_window = data_preprocess(thr, sliding_window, MAX) # identify the truning point and make a preprocessing
			k = len(wraps)
			ntime = tHistory[-1]+1
			one_time_forecast(new_window, tHistory, ntime, k, predictions, MAX)'''
			if predictions[-1] < 0: predictions[-1] = 0
			
		#lambda elapsed:  time.sleep(1-elapsed) if elapsed < 1 else time.sleep(0)
		time.sleep(pr)
		#end = time.monotonic()
		#elapsed = end-start
		#print(elapsed)
	diff = eliminate_trans_error(chps_ind, actual, predictions)
	if math.isnan(diff[-1]) or math.isnan(diff[-4]):
		logging.info('Packet loss: {a}'.format(a= ip))
		code = 1
		return code, dst_ip
	# here design a test: no error, manually subtract n to the predcition errors
	err1 = diff[-(td+1)]
	p = 0.02
	err2 = diff[-1]
	status = None
	status = detect_new(err1, p, err2, u, s, n)
	print('status: ', status, n)
	
	dataset['cu'].append(cu)
	dataset['ip'].append(ip)
	dataset['mae'].append(mae)
	dataset['smape'].append(smape)
	dataset['n'].append(n)
	dataset['dst_ip'].append(dst_ip)
	dataset['td'].append(td)
	dataset['status'].append(status)
	#print(ip, dst_ip, status, astatus)
	logging.info('{a} | {b} | {c} | {d}'.format(a= ip, b = dst_ip, c = actual, d = predictions))
	return code, dst_ip
	
def fill_miss_values(data):
	s = pd.Series(data)
	s = s.interpolate(method='pad')
	return (s.interpolate(method='linear', limit_direction ='both').values % 65536).tolist()
	

def extract_ssh_servers():
	data = pd.read_csv('../ipid_prediction/Dataset/online_analysis/ssh_port22_server/ssh_22.csv')
	ips = data.iloc[:,1].values
	count = 0
	f = open('../ipid_prediction/Dataset/online_analysis/sshserver_ips.test.data', 'w')
	for ip in ips:
		f.write(ip+'\n')
		count = count + 1
		if count == 3000: break
	f.close()
		
	
	
	
def test():
	dataset = {
	'ip': [],
	'mae': [], 
	'smape': [],
	'n': [],
	'dst_ip': [],
	'status': [],
	'astatus': [],
	}
	#with open('../ipid_prediction/evaluate/online_analysis/lr.reflectors.(low).res', 'r') as filehandle:
	with open('../ipid_prediction/Dataset/online_analysis/reflectors_global.data.res', 'r') as filehandle:	
		filecontents = filehandle.readlines()
		for line in filecontents:
			fields = line.split(",")
			if len(fields) < 1 : continue
			ip = fields[0].strip('\n')
			protocol = 'tcp'
			port = 80
			ns = ''
			dst_ip = '198.22.162.67' # an IP we control
			dst_port = 80
			single_port_scan(ip, protocol, port, ns, dst_ip, dst_port, False, dataset)
			#dst_port = 44345
			#single_ip_forecast(ip, protocol, port, ns, dst_ip, dst_port, True)

lib = cdll.LoadLibrary("./ipid_pred_lib.so")
logging.basicConfig(level=logging.INFO, filename='./test_reflectors.log')
#f = open('./ipid_port_scan.lr.test_pred_n.res', 'w')
def main():
	#analysis02()
	#test_web_servers()
	#start = time.monotonic()
	#fast_scan()
	#end = time.monotonic()
	#logging.info('Total of time: {a}'.format(a = (end-start)/60))
	#fast_scan_fp_res()
	#extract_ssh_servers()
	#extract_web_servers()
	#collect_ground_truth_data_ICLab()
	#censor_measure()
	#test_reflectors()
	test_reflectors_analysis()
	#filter_unreachable_webservers()
	#filter_urls()
	#compute_RTO()

def compute_RTO():
	ips, ports = list(), list()
	with open('./ooni_ip_blocking_2022_final.csv') as filehandle:
			filecontents = filehandle.readlines()
			for line in filecontents:
				fields = line.split(",")
				if len(fields) < 6 : continue
				ip = fields[4]
				port = fields[5].strip('\n')
				ips.append(ip)
				ports.append(int(port))
				
	with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
		futures = []
		for ip, port in zip(ips, ports):
			futures.append(executor.submit(compute_td, ip, port))
		for future in concurrent.futures.as_completed(futures):
			res = future.result()
			print(res)
	
def filter_unreachable_webservers():
	'''f = open('./ooni_ip_blocking_2022_filtered.csv', 'w')
	ips = list()
	ports = list()
	with open('./ooni_ip_blocking_2022_new.csv') as filehandle:
			filecontents = filehandle.readlines()
			for line in filecontents:
				fields = line.split(",")
				if len(fields) < 6 : continue
				dst_ip = fields[4]
				dst_port = fields[5].strip('\n')
				ips.append(dst_ip)
				ports.append(int(dst_port))
	
	with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
		futures = []
		for dst_ip, dst_port in zip(ips, ports):
			futures.append(executor.submit(test_dst_port, dst_ip, 'tcp', 'S', dst_port, ''))
		for future in concurrent.futures.as_completed(futures):
			res, dst_ip = future.result()
			if res == 'open':
				f.write(dst_ip+'\n')
	f.close()'''
	
	
	ips = list()
	with open('../censorship_measurement/ooni_ip_blocking_2022_filtered.csv') as filehandle:
			filecontents = filehandle.readlines()
			for line in filecontents:
				ip = line.strip('\n')
				ips.append(ip)
	
	f = open('../censorship_measurement/ooni_ip_blocking_2022_final.csv', 'w')
	with open('../censorship_measurement/ooni_ip_blocking_2022_new.csv') as filehandle:
			filecontents = filehandle.readlines()
			for line in filecontents:
				fields = line.split(",")
				if len(fields) < 6 : continue
				dst_ip = fields[4]
				if dst_ip not in ips: continue
				f.write(line)
	f.close()
			
				

def filter_urls():
	res = {}
	f = open('../censorship_measurement/ooni_validation/ooni_20220218_filtered.csv', 'w')
	with open('../censorship_measurement/ooni_validation/ooni_20220218_original.csv') as filehandle:
			filecontents = filehandle.readlines()
			for line in filecontents:
				fields = line.split(",")
				if len(fields) < 6 : continue
				ip = fields[4]
				g = ip.split('.')
				if len(g) < 4: continue
				f.write(line)
				cu = fields[1]
				if cu not in res: 
					res[cu] = 1
				else:
					res[cu] = res[cu] + 1
				#if cu not in ['CA', 'IR', 'MM', 'ET', 'NL', 'CN', 'RU']: continue
				#f.write(line)
	x = list()			
	y = list()
	for cu in res:
		print(cu, res[cu])
		x.append(cu)
		y.append(res[cu])
	Z = [x for _,x in sorted(zip(y,x))]
	print(Z)
	f.close()
	
	'''
	res = {}
	f = open('../censorship_measurement/final_test_list/ooni_ip_blocking_2022_test_list.csv', 'w')
	with open('../censorship_measurement/ooni_ip_blocking_2022_final.dat') as filehandle:
			filecontents = filehandle.readlines()
			for line in filecontents:
				fields = line.split(",")
				if len(fields) < 7 : continue
				td = fields[6].strip('\n')
				item = fields[0] +','+fields[1] +','+fields[2] +','+fields[3] +','+fields[4] +','+fields[5]
				if item not in res:
					res[item] = list()
				res[item].append(td)
	for item in res:
		f.write(item+','+str(res[item])+'\n')
	f.close()
	'''
	

def load_cuToRef_old(cuToRef):
	
	with open('./iclab_ip_OutOrIn_blocking_reflectors.dat', 'r') as filehandle:
		filecontents = filehandle.readlines()
		for line in filecontents:
			fields = line.split(",")
			if len(fields) < 3: continue
			as_number = fields[0]
			ip = fields[1]
			pred = float(fields[2])
			if pred >= 0.999:
				obj = IPWhois(ip)
				res=obj.lookup_whois()
				cu = res["nets"][0]['country']
				if cu not in cuToRef:
					cuToRef[cu] = {
					'reflectors': [],
					'net': [],
					'urls': [],
					'webservers': [],
					}
				g = ip.split('.')
				if len(g) < 4: continue
				if g[3] != '0': g[3] = '0'
				net = g[0]+'.'+g[1]+'.'+g[2]+'.'+ g[3]
				if net not in cuToRef[cu]['net']:
					if len(cuToRef[cu]['reflectors']) > 100: continue
					cuToRef[cu]['net'].append(net) 
					cuToRef[cu]['reflectors'].append(ip)

def load_cuToRef(cuToRef, ifile):
	with open(ifile, 'r') as filehandle:
		filecontents = filehandle.readlines()
		for line in filecontents:
			fields = line.split(",")
			if len(fields) < 2 : continue
			cu = fields[0]
			ip = fields[2]
			if cu not in cuToRef:
				cuToRef[cu] = {
				'reflectors': [],
				'urls': [],
				'services': [],
				}
			cuToRef[cu]['reflectors'].append(ip)

def load_testList(cuToRef, ifile):
	with open(ifile, 'r') as filehandle:
		filecontents = filehandle.readlines()
		for i, line in enumerate(filecontents):
			fields = line.split(",")
			if len(fields) < 6: continue
			cu = fields[1]
			if cu not in cuToRef: continue
			if len(cuToRef[cu]['reflectors']) == 0: continue
			url = fields[3]
			dst_ip = fields[4]
			dst_port = fields[5].strip('\n')
			dest = dst_ip+':'+dst_port
			g = dst_ip.split('.')
			if len(g) < 4: continue
			cuToRef[cu]['urls'].append(url)
			cuToRef[cu]['services'].append(dest)

def test_reflectors():
	ips_list = list()
	domains_list = list()
	ips = list()
	domains = list()
	with open('./ooni_ip_blocking_2022_reflectors.dat', 'r') as filehandle: # ./lr.reflectors.(low).res, scan_target_reflectors.res
		filecontents = filehandle.readlines()
		for line in filecontents:
			fields = line.split(",")
			if len(fields) < 2 : continue
			domain = ''
			ip = fields[2] 
			domains.append(domain)
			ips.append(ip)
			if len(ips) == 50: #10
				ips_list.append(ips)
				domains_list.append(domains)
				ips = list()
				domains = list()
	ips_list.append(ips)
	domains_list.append(domains)
	protocol = 'tcp'
	port = random.randrange(10000, 65535, 1) 
	#port = 80
	dst_ip = '199.244.49.62'
	td = random.randrange(1, 3, 1) #1, 2, 3, 4
	dst_port = 80
	dataset = {
		'ip': [],
		'mae': [], 
		'smape': [],
		'n': [],
		'dst_ip': [],
		'status': [],
	}
	
	with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
		futures = []
		for ips, domains in zip(ips_list, domains_list):
			random.shuffle(ips)
			futures.append(executor.submit(group_ips_measure, ips, protocol, port, domains, dst_ip, dst_port, td, 30, False, dataset))
		for future in concurrent.futures.as_completed(futures):
			print('Done!')
	df = pd.DataFrame(dataset)
	df.to_csv('./test_ooni_ip_blocking_2022_reflectors_in_block.res', index=False)

def test_reflectors_analysis():
	f = open('../censorship_measurement/manual_validation/test_ooni_ip_blocking_2022_reflectors_refined.res', 'w')
	c = 0
	n = 0
	ips = list()
	mips = list()
	with open('../censorship_measurement/manual_validation/test_ooni_ip_blocking_2022_reflectors_out_block.res') as filehandle:
			filecontents = filehandle.readlines()
			n = len(filecontents)
			for i, line in enumerate(filecontents):
				if i == 0: continue
				fields = line.split(",")
				if len(fields) < 6 : continue
				ip = fields[0]
				res = fields[5]
				if 'outbound blocking' not in res: continue
				c = c +1 
				ips.append(ip)
				if ip not in mips: 
					mips.append(ip)
				
	print('out block: ', c, n, c/n)
	c, n = 0, 0
	merged_ips = list()
	with open('../censorship_measurement/manual_validation/test_ooni_ip_blocking_2022_reflectors_in_block.res') as filehandle:
			filecontents = filehandle.readlines()
			n = len(filecontents)
			for i, line in enumerate(filecontents):
				if i == 0: continue
				fields = line.split(",")
				if len(fields) < 6 : continue
				ip = fields[0]
				res = fields[5]
				if 'inbound blocking' not in res: continue
				c = c +1 
				if ip not in mips: 
					mips.append(ip)
				if ip not in ips: continue
				merged_ips.append(ip)
				
	print('in block: ', c, n, c/n)
	
	c, n = 0, 0
	final_ips = list()
	with open('../censorship_measurement/manual_validation/test_ooni_ip_blocking_2022_reflectors_no_block.res') as filehandle:
			filecontents = filehandle.readlines()
			n = len(filecontents)
			for i, line in enumerate(filecontents):
				if i == 0: continue
				fields = line.split(",")
				if len(fields) < 6 : continue
				ip = fields[0]
				res = fields[5]
				if 'no blocked' not in res: continue
				c = c +1 
				if ip not in mips: 
					mips.append(ip)
				if ip not in merged_ips: continue
				f.write(line)
				final_ips.append(ip)
	print('no block: ', c, n, c/n)
	
	f.close()
	
def compute_tds(services):
	tds = list()
	with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
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
	
def censor_measure():
	#load reflectors
	cuToRef = {}
	ifile = './ooni_ip_blocking_2022_reflectors.final.res'
	load_cuToRef(cuToRef, ifile)
	ifile = './ooni_20220218_filtered.csv'
	load_testList(cuToRef, ifile)
	webservers = list()
	dataset = {
		'cu': [],
		'ip': [],
		'mae': [], 
		'smape': [],
		'n': [],
		'dst_ip': [],
		'status': [],
		'td': [],
	}
	
	#random.shuffle(reflectors) # randomly resorted
	for cu in cuToRef:
		services = cuToRef[cu]['services']
		if len(services) == 0: continue
		reflectors = cuToRef[cu]['reflectors']
		random.shuffle(reflectors) 
		n1 = len(services)
		n2 = len(reflectors)
		n = int(n1/n2)
		for i in range(n):
			subreflectors= reflectors
			start = i*n2
			end = (i+1) * n2
			subservices = services[start:end]
			start_measure(subreflectors, subservices, dataset, cu)
				
		rest = n1 % n2
		if rest > 0:
			subreflectors = reflectors[0:rest]
			subservices = services[-rest:]
			start_measure(subreflectors, subservices, dataset, cu)
	df = pd.DataFrame(dataset)
	df.to_csv('./test_censor_measure.res', index=False)

def start_measure(reflectors, services, dataset, cu):
	protocol = 'tcp'
	port = random.randrange(10000, 65535, 1)
	ns = ''
	#dst_port = 80
	#dst_port = 22
	with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
		futures = []
		for ip, service in zip(reflectors,services):
			fields = service.split(':')
			dst_ip = fields[0]
			dst_port = int(fields[1])
			futures.append(executor.submit(single_port_scan, ip, protocol, port, ns, dst_ip, dst_port, 30, True, dataset, cu))
		for future in concurrent.futures.as_completed(futures):
			code, dst_ip = future.result()
			
def test_webservers():
	webservers = list()
	dst_ports = list()
	with open('./ooni_IR_inbound_blocking_test_websites.dat', 'r') as filehandle:
		filecontents = filehandle.readlines()
		for i, line in enumerate(filecontents):
			fields = line.split(",")
			if len(fields) < 4: continue
			url = fields[2]
			dst_port = 80
			if 'https' in url:
				dst_port = 443
			dst_ports.append(dst_port)
			dst_ip = fields[3].strip('\n')
			g = dst_ip.split('.')
			if len(g) < 4: continue
			webservers.append(dst_ip)
	ip = '94.183.134.37'
	protocol = 'tcp'
	port = random.randrange(10000, 65535, 1) 
	ns = ''
	dataset = {
		'ip': [],
		'mae': [], 
		'smape': [],
		'n': [],
		'dst_ip': [],
		'status': [],
		'astatus': [],
	}
	
	for dst_ip, dst_port in zip(webservers, dst_ports):
		td = 1
		our_ip = '199.244.49.62'
		our_port = 80
		controlled_experiment(ip, protocol, port, ns, our_ip, our_port, td, 30, True, dataset)
		td = compute_td(dst_ip, dst_port)
		single_port_scan(ip, protocol, port, ns, dst_ip, dst_port, td, 30, True, dataset)

	df = pd.DataFrame(dataset)
	df.to_csv('./test_ooni_IR_webservers_block.res', index=False)
			


def collect_ground_truth_data_OONI(): # extract jsonl file
	f = open('../censorship_measurement/censored_websites_merged.csv', 'w')
	res = list()
	with open('../censorship_measurement/censored_websites_merged.res', 'r') as filehandle:	
		filecontents = filehandle.readlines()
		for i, line in enumerate(filecontents):
			fields = line.split(",")
			#if i == 0: continue
			if len(fields) < 1 : continue
			if country+','+asn+','+ip in res: continue
			f.write(country+','+asn+','+url+','+ip+'\n')
			res.append(country+','+asn+','+ip)
	
	

def collect_ground_truth_data_ICLab():
	f = open('../censorship_measurement/iclab_ir_ip_blocking_data.csv', 'w')
	
	path = '../censorship_measurement/'
	for filename in glob.glob(os.path.join(path, '*_fin.csv')):
		asn = list()
		countries = list()
		data = {}
		res =  list()
		#with open('../censorship_measurement/iclab_results_2020-06-01_2020-07-01_fin.csv', 'r') as filehandle:
		print(filename)
		with open(filename, 'r') as filehandle:	
			filecontents = filehandle.readlines()
			print(len(filecontents))
			for i, line in enumerate(filecontents):
				fields = line.split(",")
				if i == 0: continue
				if len(fields) < 22 : continue
				country = fields[2]
				#print(country)
				if country != 'ir' or country != 'cn': continue
				as_number = fields[3]
				url = fields[5]
				ipstr = fields[11].split('\'')
				ip = ''
				if len(ipstr) == 3:
					ip = ipstr[1]
				#print(ip)
				pj = fields[17]
				censored = fields[21]
				#f.write(line)
				print(pj)
				if pj == 'probably censored' and censored.strip('\n') == 'true':
					print('Found')
					if country+','+as_number+','+ip in res: continue
					if country not in countries:
						countries.append(country)
					if as_number not in asn: 
						asn.append(as_number)
					f.write(country+','+'AS'+as_number+','+url+','+ip+'\n')
					res.append(country+','+as_number+','+ip)
					#f.write(line)
		print(len(asn))
		print(len(countries))
		
	f.close()
	
	'''data = {}
	with open('../censorship_measurement/iclab_ip_blocking_data.csv', 'r') as filehandle:	
		filecontents = filehandle.readlines()
		for i, line in enumerate(filecontents):
			fields = line.split(",")
			#if i == 0: continue
			if len(fields) < 1 : continue
			country = fields[0]
			as_number = fields[1]
			url = fields[2]
			target = country + as_number
			if target not in data: 
				data[target] = list()
			if url in data[target]: continue
			data[target].append(url)
	targets = list()
	for k in data:
		print(k, len(data[k]))
		if len(data[k]) < 100: continue
		targets.append(k)
	print(len(targets))
	countries = list()
	new_asn = list()
	
	f = open('../censorship_measurement/iclab_ip_blocking_subdata.csv', 'w')
	with open('../censorship_measurement/iclab_ip_blocking_data.csv', 'r') as filehandle:	
		filecontents = filehandle.readlines()
		for i, line in enumerate(filecontents):
			fields = line.split(",")
			#if i == 0: continue
			if len(fields) < 1 : continue
			country = fields[0]
			as_number = fields[1]
			target = country+as_number
			if target not in targets: continue
			if country not in countries:
				countries.append(country)
			if as_number not in new_asn: 
				new_asn.append(as_number)
			url = fields[2]
			
			f.write(line)
	print(countries)
	print(new_asn)
	
	f.close()'''
	
	'''countries = list()
	new_asn = list()
	f = open('../censorship_measurement/iclab_no_blocking_miniset.csv', 'w')
	with open('../censorship_measurement/iclab_no_blocking_subdata.csv', 'r') as filehandle:	
		filecontents = filehandle.readlines()
		rands = random.sample(range(0, len(filecontents)), 2000)
		for i, line in enumerate(filecontents):
			if i not in rands: continue
			fields = line.split(",")
			#if i == 0: continue
			if len(fields) < 1 : continue
			country = fields[0]
			as_number = fields[1]
			target = country+as_number
			#if target not in targets: continue
			if country not in countries:
				countries.append(country)
			if as_number not in new_asn: 
				new_asn.append(as_number)
			url = fields[2]
			
			f.write(line)
	print(countries)
	print(new_asn)
	
	f.close()'''

def extract_web_servers():
	ips = list()
	f = open('../ipid_prediction/Dataset/online_analysis/webserver_ips.target.data', 'w')
	with open('../ipid_prediction/Dataset/online_analysis/webserver_ips.rest.data', 'r') as filehandle:
	#with open('../evaluate/data/http_80.ip.data.new', 'r') as filehandle:	
		filecontents = filehandle.readlines()
		rands = random.sample(range(0, len(filecontents)), 5000)
		for i, line in enumerate(filecontents):
			if i not in rands: continue
			fields = line.split(",")
			if len(fields) < 1 : continue
			ip = fields[0].strip('\n')
			if ip in ips: continue
			ips.append(ip)
			f.write(ip+'\n') 
	f.close()
	


def fast_scan():
	
	n = 100
	reflectors = list() 
	with open('./scan_target_reflectors.merged.res') as f1: ## less than 10 sampled packets
		filecontents = f1.readlines()
		for line in filecontents:
			fields = line.split(",")
			if len(fields) < 1 : continue
			ip = fields[0].strip('\n')
			reflectors.append(ip)
	webservers = list()
	
	dataset = {
		'ip': [],
		'mae': [], 
		'smape': [],
		'n': [],
		'dst_ip': [],
		'status': [],
		'astatus': [],
	}
	random.shuffle(reflectors) # randomly resorted
	with open('./webserver_ips.target.data') as f2: #./lr.fast_scan.p80.fn.res.res webserver_ips.target.data
		filecontents = f2.readlines()
		for line in filecontents:
			fields = line.split(",")
			if len(fields) < 1 : continue
			ip = fields[0].strip('\n')
			webservers.append(ip)
			if len(webservers) == n:
				subwindow = reflectors[0:n]
				reflectors = reflectors[n:] + subwindow ## pop the prior 100 servers and push them at the end of the previous reflectors window
				start_measure(subwindow, webservers, dataset)
				webservers.clear()
				continue
		if len(webservers) > 0: 
			subwindow = reflectors[0:len(webservers)]
			start_measure(subwindow, webservers, dataset)
	df = pd.DataFrame(dataset)
	df.to_csv('./ipid_port_scan.lr.web_servers.p44345.res', index=False) #ratelimit
	
def fast_scan_fn_res():
	res = {}
	
	with open('../ipid_prediction/evaluate/online_analysis/ipid_port_scan.lr.web_servers.p80.res') as filehandle:
		filecontents = filehandle.readlines()
		for line in filecontents:
			if line == filecontents[0]: continue
			fields = line.split(",")
			if len(fields) < 7 : continue
			ip = fields[4]
			status = fields[5]
			astatus = fields[6].strip('\n')
			if astatus == 'closed': continue
			s = 0
			if 'open' in status:
				s = 1	
			if ip in res: 
				res[ip]['status'].append(s)
			else:
				res[ip] = dict({
					'status': [s],
					})
	f = open('../ipid_prediction/evaluate/online_analysis/lr.fast_scan.p80.res', 'w')
	f1 = open('../ipid_prediction/evaluate/online_analysis/lr.fast_scan.p80.fn.res', 'w')
	c = 0
	for ip in res:
		r = res[ip]['status']
		g = sum(r)
		s = ' '
		if g >= 1:
			s = 'open'
			c = c +1
		else:
			s = 'closed or filtered'
			f1.write(ip+'\n')
			
		f.write(ip+','+s+'\n')
	print(c)
	f.close()
	f1.close()

def fast_scan_fp_res():
	res = {}
	for i in range(1):
		with open('../ipid_prediction/evaluate/online_analysis/ipid_port_scan.lr.web_servers.p44345.res') as filehandle:
			filecontents = filehandle.readlines()
			for line in filecontents:
				if line == filecontents[0]: continue
				fields = line.split(",")
				if len(fields) < 7 : continue
				ip = fields[4]
				status = fields[5]
				astatus = fields[6].strip('\n')
				if astatus == 'open': continue
				s = 0
				if 'open' in status:
					s = 1	
				if ip in res: 
					res[ip]['status'].append(s)
				else:
					res[ip] = dict({
						'status': [s],
						})
				
	f = open('../ipid_prediction/evaluate/online_analysis/lr.fast_scan.p44345.res', 'w')
	f1 = open('../ipid_prediction/evaluate/online_analysis/lr.fast_scan.p44345.fp.res', 'w')
	c = 0
	for ip in res:
		g = np.sum(res[ip]['status'])
		#print(ip, g)
		s = ' '
		if g >= 1:
			s = 'open'
			f1.write(ip+'\n')
		else:
			s = 'closed or filtered'
			c = c +1				
		
		f.write(ip+','+s+'\n')
	print(c)
	f.close()
	f1.close()

def analysis01():
	ips = list()
	smapes = list()
	nums= list()
	f = open('../ipid_prediction/Dataset/online_analysis/scan_target_reflectors.03.res', 'w')
	f1 = open('../ipid_prediction/Dataset/online_analysis/scan_target_reflectors.g1.res', 'w')
	f2 = open('../ipid_prediction/Dataset/online_analysis/scan_target_reflectors.g2.res', 'w')
	for l in range(30, 31):
		with open('../ipid_prediction/evaluate/online_analysis/ipid_port_scan.lr.spoofing.03.res') as filehandle: # 'str(l)'
				filecontents = filehandle.readlines()
				c = 0.0
				nega = 0.0
				for i, line in enumerate(filecontents):
					if i == 0 : continue
					fields = line.split(",")
					if len(fields) < 6 : continue
					c = c + 1
					ip = fields[0]
					status = fields[5].strip('\n')
					if status == 'closed or filtered port!':
						ips.append(ip)
						nega = nega + 1
					if status == 'open port':
						smapes.append(round(float(fields[2]),5))
						nums.append(float(fields[3]))
						f.write(line)
				print('False negative: ', c, nega, nega/c)
						
	f.close()
	f1.close()
	f2.close()
				
	#print('False negative: ', nega/count)
	'''sort_indices = np.argsort(smapes)
	smapes.sort()
	sorted_nums = list()
	for i in sort_indices:
		sorted_nums.append(nums[i])
	print(len(sorted_nums))
	sns.lineplot(smapes, sorted_nums)'''
	print(np.median(nums))
	#sns.boxplot(data = nums, showfliers=False)
	#plt.show()
	'''f = open('../ipid_prediction/evaluate/online_analysis/ipid_port_scan.lr.nega.log', 'w')
	with open('../ipid_prediction/evaluate/online_analysis/ipid_port_scan.lr.test.log') as filehandle:
			filecontents = filehandle.readlines()
			for line in filecontents:
				fields = line.split("|")
				if len(fields) < 3: continue
				ip = fields[0].split(':')[-1].strip(' ')
				if ip not in ips: continue
				f.write(line)
	f.close()'''

def analysis02():
	posi = 0.0
	count = 0.0
	ips = list()
	smapes = list()
	nums= list()
	
	with open('../ipid_prediction/Dataset/online_analysis/scan_target_reflectors.03.res') as filehandle:
			filecontents = filehandle.readlines()
			for line in filecontents:
				fields = line.split(",")
				if len(fields) < 6 : continue
				ip = fields[0]
				ips.append(ip)
	print(len(ips))
	f = open('../ipid_prediction/Dataset/online_analysis/scan_target_reflectors.new.03.res', 'w')
	for l in range(30, 31):
		with open('../ipid_prediction/evaluate/online_analysis/ipid_port_scan.lr.no.spoofing.03.res') as filehandle:
				filecontents = filehandle.readlines()
				posi = 0.0
				count = 0.0
				for i, line in enumerate(filecontents):
					if i == 0 : continue
					fields = line.split(",")
					if len(fields) < 6 : continue
					count = count + 1
					ip = fields[0]
					status = fields[5].strip('\n')
					if status == 'open port':
						posi = posi + 1
					else:
						if ip in ips and float(fields[3]) < 10:
							f.write(line)
					
		print('False positive: ', count, posi, posi/count)
	
	
	f.close()

	
			
if __name__ == "__main__":
    # execute only if run as a script
    main()


