import numpy as np
import matplotlib.pyplot as plt
import re
import tsfel
import pandas as pd
import math
from random import randrange
import random
import os
import glob
from scipy.stats import entropy


def average(data):
	return round(sum(data)/len(data), 3)

def weighted_average(data, seg_len):
	#a = np.array(data)
	return round(np.dot(data, seg_len / np.sum(seg_len)), 3)
	

def rela_diff(a, b, MAX):
	return (b + MAX - a)%MAX


def extract(string_arr):
	arr = []
	matches = re.findall(regex, string_arr)
	for match in matches:
		arr.append(int(match))
	return arr

def split_s(ids):
	ids1 = []
	ids2 = []
	for i in range(0, len(ids)):
		if i % 2 == 0:
			ids1.append(ids[i])
		else:
			ids2.append(ids[i])
	return ids1, ids2

def split(ids, times):
	ids1 = []
	ids2 = []
	times1 = []
	times2 = []
	for i in range(0, len(ids)):
		if i % 2 == 0:
			ids1.append(ids[i])
			times1.append(times[i])
		else:
			ids2.append(ids[i])
			times2.append(times[i])
	return ids1, times1, ids2, times2

def count_ipid_wraps(data):
	count = 0
	for i in range(0, len(data)-1):
		#if data[i] == -1 or data[i+1] == -1: continue
		if data[i+1]-data[i] < 0:
			count = count + 1
	return count
	
def computeIpidVelocity(ids, times, MAX):
# the mean of relative differences between two consecutive IP ID values  
	spd = float(0)

	for i in range(0, len(ids)-1):
		
		gap = float(rela_diff(ids[i], ids[i+1], MAX))
		#dur = float(times[i+1]-times[i])/1000000000.0 #unit: ID/s
		dur = 1
		spd += gap/dur
	
	spd /= float(len(ids)-1)
	
	return round(spd, 3)

def max_increment(ids, MAX):
	diffs = []
	for i in range(0, len(ids)-1):
		diff = rela_diff(ids[i], ids[i+1], MAX)
		diffs.append(diff)
	return max(diffs)

def autocorr(data):
	s = pd.Series(data)
	auto_corr = s.autocorr(lag=1)
	if math.isnan(auto_corr):
		return 0
	else:
		return round(auto_corr, 3)

def crosscorr(x, y):
	s1 = pd.Series(x)
	s2 = pd.Series(y)
	cross_corr = s1.corr(s2)
	if math.isnan(cross_corr): 
		return 0
	else: 
		return round(cross_corr, 3)

def power_bandwidth(data, fs):
	return round(tsfel.feature_extraction.features.power_bandwidth(data, fs), 3)

def spectral_roll_off(fmg, f):
    cum_ff = np.cumsum(fmg)
    value = 0.85 * (np.sum(fmg))
    return round(f[np.where(cum_ff >= value)[0][0]],3)
			
def extreme_loss(ids, times, loss_rate):
	new_ids = []
	new_times = []
	n = int(len(ids)*loss_rate)
	start_point = len(ids)-n
	for i in range(len(ids)):
		if i >= start_point and i < start_point + n:
			new_ids.append(-1)
			new_times.append(times[i])
			continue
		new_ids.append(ids[i])
		new_times.append(times[i])
	return new_ids, new_times


def random_loss(ids, times, loss_rate):
	n = int(len(ids) * loss_rate)
	new_ids = []
	new_times = []
	rands = random.sample(range(0, len(ids)), n)
	for i in range(len(ids)):
		if i in rands:
			new_ids.append(-1)
			new_times.append(times[i])
			continue
		new_ids.append(ids[i])
		new_times.append(times[i])

	return new_ids, new_times


switcher = {
	'global': 1,
	'high_vel': 1,
	'perConn': 2,
	'random': 3,
	'constant':4,
	'nonStandard': 5,
	'test': 9,
}

def write_to_dic(dataset, c, ip, num_wrap, v, max_inc, max_inc1, max_inc2, autocorr, crosscorr, fd, b, fc, fr):
	ipid_class = switcher[c]
	dataset['ip'].append(ip)
	dataset['num_wrap'].append(num_wrap)
	dataset['v'].append(v)
	dataset['max_inc'].append(max_inc)
	dataset['max_inc1'].append(max_inc1)
	dataset['max_inc2'].append(max_inc2)
	dataset['autocorr'].append(autocorr)
	#dataset['crosscorr'].append(crosscorr)
	dataset['b'].append(b)
	dataset['fd'].append(fd)
	#dataset['fc'].append(fc)
	dataset['fr'].append(fr)
	dataset['class'].append(ipid_class)

def segment_features(ids, times, features, seg_len, sampling_rate, MAX):
	y1, y2 = split_s(ids)
	num_wrap = count_ipid_wraps(y1)/len(y1) # distinguish between perConn and random or load-balancing
	v = computeIpidVelocity(ids, times, MAX) 
	max_inc = max_increment(ids, times, MAX) 
	ids1, times1, ids2, times2 = split(ids, times)
	max_inc1 = max_increment(ids1, times1, MAX) 
	max_inc2 = max_increment(ids2, times2, MAX) 
	auto_corr = autocorr(ids) 
	#cross_corr = crosscorr(ids1, ids2)
	
	data = np.array(ids, dtype=float)
	data[:] = data - np.mean(data) #remove zero freqeuncy
	fourier_transform = np.fft.fft(data)
	abs_fourier_transform = np.abs(fourier_transform)
	power_spectrum = np.square(abs_fourier_transform)
	N = len(data)
	
	frequency = np.linspace(0, sampling_rate, N)
	fqs = frequency[:N//2+1]
	fqs = fqs / sampling_rate
	ps = power_spectrum[:N//2+1]
	max_index = np.argmax(ps)
	fd = round(fqs[max_index], 3)
	b = power_bandwidth(data, 1)
	fmg = abs_fourier_transform[:N//2+1]
	#fc = spectral_centroid(fmg, fqs)
	fr = spectral_roll_off(fmg, fqs)
	
	features['num_wrap'].append(num_wrap)
	features['v'].append(v)
	features['max_inc'].append(max_inc)
	features['max_inc1'].append(max_inc1)
	features['max_inc2'].append(max_inc2)
	features['autocorr'].append(auto_corr)
	#features['crosscorr'].append(cross_corr)
	features['b'].append(b)
	features['fd'].append(fd)
	#features['fc'].append(fc)
	features['fr'].append(fr)
	seg_len.append(len(ids))
	
def compute_segment_feature(ids, times, sampling_rate, MAX):
	id_segment = []
	time_segment = []
	features ={
		'num_wrap': [],
		'v': [],
   		'max_inc': [],
   		'max_inc1': [],
		'max_inc2': [],
		'autocorr': [],
		#'crosscorr':[],
		'b':[],
		'fd':[],
		#'fc':[],
		'fr':[]
	}
	seg_len = []
	for i in range(len(ids)):
		if ids[i] == -1:
			if len(id_segment) >= 4:
				segment_features(id_segment, time_segment, features, seg_len, sampling_rate, MAX)
			id_segment = []
			time_segment = []
			continue
		id_segment.append(ids[i])
		time_segment.append(times[i])
	
	if len(id_segment) >= 4:# for the sequence without packet loss
		segment_features(id_segment, time_segment, features, seg_len, sampling_rate, MAX)
		
	return features, seg_len

regex = r"[0-9]+|-1"	
	
def feature_extraction():		
	T = 1
	models = ['extreme']
	classes = ['constant', 'global', 'perConn', 'random', 'nonStandard']
	#classes = ['high_vel']
	#length = [5, 15, 25, 35, 45, 55, 65, 75, 85, 95]
	length = [100]
	for l in length:
		for m in models: 
			dataset ={
				'ip': [],
				'num_wrap': [],
				'v': [],
		   		'max_inc': [],
		   		'max_inc1': [],
				'max_inc2': [],
				'autocorr': [],
				#'crosscorr':[],
				'b':[],
				'fd':[],
				#'fc':[],
				'fr':[],
				'class': []
				}
			for c in classes:
				with open('../Original_Dataset/'+c+'.data', 'r') as filehandle:	#'.1000.data'
					filecontents = filehandle.readlines()
					for line in filecontents:
						fields = line.split(",")
						if len(fields) < 3 : continue
						ip = fields[0]
						ids = extract(fields[1])
						MAX = 65536
						if max(ids) < 32768 : MAX = 32768
						times = extract(fields[2])
					
						if m=='extreme':
							ids, times = extreme_loss(ids, times, 1-l/float(100))
							
						sampling_rate = 1/ T
						features, seg_len = compute_segment_feature(ids, times, sampling_rate, MAX)
						if len(features.get('v')) == 0: 
							continue
						num_wrap = np.median(features.get('num_wrap'))
						v = np.median(features.get('v'))
						max_inc = max(features.get('max_inc'))
						max_inc1 = max(features.get('max_inc1'))
						max_inc2 = max(features.get('max_inc2'))
						auto_corr = np.median(features.get('autocorr'))
						#cross_corr = np.median(features.get('crosscorr'))
						b = np.median(features.get('b'))
						fd = np.median(features.get('fd'))
						#fc = np.median(features.get('fc'))
						fr = np.median(features.get('fr'))
						write_to_dic(dataset, c, ip = ip, v=v, max_inc=max_inc, max_inc1=max_inc1, max_inc2=max_inc2, autocorr=auto_corr, crosscorr=cross_corr, fd=fd, b=b, fc=fc, fr=fr)
		df = pd.DataFrame(dataset)
		df.to_csv('./ipid_new_data_all_9f.csv', index=False)

def generate_loss_data():
	loss_rates = [0.05, 0.10, 0.15, 0.20]
	models = ['random']
	classes = ['constant', 'global', 'perConn', 'random', 'nonStandard']
	for loss_rate in loss_rates:
		for model in models:
			f = open('./'+model+'.loss.'+str(loss_rate)+'.data', 'w')
			for c in classes:
				with open('../under-sampled-dataset/'+c+'.660.data', 'r') as filehandle:	
					filecontents = filehandle.readlines()
					for line in filecontents:
						fields = line.split(",")
						if len(fields) < 3 : continue
						ip = fields[0]
						ids = extract(fields[1])
						times = extract(fields[2])
						
						if model == 'random':
							ids, times = random_loss(ids, times, loss_rate = loss_rate)
						ids_str = ' '.join(map(str, ids))
						times_str = ' '.join(map(str, times))
						
						f.write(ip+',['+ids_str+'],['+times_str+']\n')
			f.close()
		
def interpolate_missing_values(data):
	#if math.isnan(data[0]): data[0] = data[1]
	s = pd.Series(data)
	s = s.interpolate(method='pad')
	return s.interpolate(method='linear', limit_direction='both').values.tolist()
		
