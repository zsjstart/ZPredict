#!/usr/bin/env python3
from numpy import array, asarray
from features_extraction_lib import extract
import numpy as np
from matplotlib import pyplot as plt
from matplotlib import pyplot
from pandas import DataFrame, concat
from ipid_prediction_lib import *
from sklearn.metrics import mean_squared_error
from math import sqrt
from sklearn import datasets, preprocessing
from neupy import algorithms
import time
import decimal
import threading
from ctypes import *
import concurrent.futures
import pandas as pd
import math
import statistics
from grnn02 import one_time_forecast02
from scipy.stats import norm
import random
import csv
import logging
from matplotlib.animation import FuncAnimation
from sklearn import linear_model
from sklearn.gaussian_process import GaussianProcessRegressor
from sklearn.gaussian_process.kernels import RBF, DotProduct, WhiteKernel, ConstantKernel as C
import warnings

lib = cdll.LoadLibrary("./ipid_pred_lib.so")
logging.basicConfig(level=logging.INFO, filename='grnn.test.log')
class go_string(Structure):
    _fields_ = [
        ("p", c_char_p),
        ("n", c_int)]
        

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
	
def sMAPE(actual, prediction):
	actual = array(actual).reshape(-1)
	prediction = array(prediction).reshape(-1)
	res = 2 * np.abs(prediction-actual) / (actual + prediction)
	after_res = list()
	for v in res:
		if math.isnan(v): continue
		after_res.append(v)
	return np.mean(after_res)

def sMAPE02(chps_ind, actual, predictions):
	res = list()
	for i in range(len(actual)):
		if i in chps_ind and abs(predictions[i]-actual[i]) > 30000:
			if predictions[i] < actual[i]:
				pre = predictions[i] + 65536
				res.append(2 * abs(pre-actual[i]) / (actual[i] + pre))
			else:
				ac = actual[i] + 65536
				res.append(2 * abs(predictions[i]-ac) / (ac + predictions[i]))
			continue
		if  (actual[i] + predictions[i]) != 0:
			res.append(2 * abs(predictions[i]-actual[i]) / (actual[i] + predictions[i]))
		else:
			res.append(0)
	after_res = list()
	for v in res:
		if math.isnan(v): continue
		after_res.append(v)
	return np.mean(after_res)
	
def walk_forward_validation(sequence, history, n_hold_out, maximum, minimum, MAX):
	train, test = train_test_split(history, n_hold_out)
	X_train, y_train = train[:, :-1], train[:, -1] # y_train shape: 1D array
	X_test, y_test = test[:, :-1], test[:, -1]
	y_train = y_train.reshape(-1, 1)
	#y_test = y_test.reshape(-1, 1)
	errs = []
	sigs = []
	#sigma = find_sigma(train)
	sigma = 0.1
	while sigma < 1.0:
		nw = algorithms.GRNN(std=sigma, verbose=False)
		nw.train(X_train, y_train)
		y_pred = nw.predict(X_test)
		
		'''y_pred = list()
		h_d = [x for x in train]
		for i in range(len(test)):
			# split test row into input and output columns
			X_test, y_test = test[i, :-1], test[i, -1]
			yhat = forecast(h_d, X_test, sigma)
			# store forecast in list of predictions
			y_pred.append(yhat)
			# add actual observation to history for the next loop
			h_d.append(test[i])
			h_d.pop(0)
		y_pred = array(y_pred)'''
		#y_test = y_test.reshape(-1)
		#y_pred = y_pred.reshape(-1)
		#diff = y_pred - y_test
		
		y_pred = denormalize(y_pred, maximum, minimum)
		actual = sequence[-n_hold_out:]
		prediction = correct(sequence,y_pred, MAX)
		#diff = np.array(prediction) - np.array(actual)
		#mae = np.mean(abs(diff))
		rmse = sqrt(mean_squared_error(actual, prediction))
		if math.isnan(rmse): 
			sigma = sigma + 0.1
			continue
		errs.append(rmse)
		sigs.append(sigma)
		sigma = sigma + 0.1
	if len(errs) == 0: return 0.1
	min_index = min( (v, i) for i, v in enumerate(errs) )[1]
	sigma = sigs[min_index]
	return sigma
	
def filter_outliers02(outlier, sequence, MAX):
	new_window = [i for i in sequence]
	if not outlier: return new_window
	for i in range(0, len(new_window)-2):
		mini_window = [new_window[i], new_window[i+1], new_window[i+2]]
		if containNAN(mini_window): continue
		delta1 = rela_diff(new_window[i], new_window[i+1], MAX)
		delta2 =  rela_diff(new_window[i+1], new_window[i+2], MAX)
		if delta1 > 10000 or delta2 > 10000: # suitable for two consecutive outliers
			mini_window = array(mini_window)
			med = np.median(mini_window)
			mini_window = abs(mini_window - med)
			max_index = max( (v, i) for i, v in enumerate(mini_window) )[1]
			new_window[i+max_index] = math.nan
			
	return new_window
	

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
	
def filter_outliers_mini(outlier, sequence, MAX):
	new_window = sequence[-3:]
	if not outlier: return 
	delta1 = rela_diff(new_window[0], new_window[1], MAX)
	delta2 =  rela_diff(new_window[1], new_window[2], MAX)
	if delta1 > 10000 or delta2 > 10000: # suitable for two consecutive outliers
		mini_window = array(new_window)
		med = np.median(mini_window)
		mini_window = abs(mini_window - med)
		max_index = max( (v, i) for i, v in enumerate(mini_window) )[1]
		sequence[-3+max_index] = math.nan

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
	

def is_outliers(u, s, diff):
	v = (diff-u)/s
	if norm.cdf(v) > 0.98 or norm.cdf(v) < 0.02: # p = 0.05
		return True
	return False

def filter_outliers_normal_distr(outlier, sequence, chps_ind, actual, predictions, outlier_ind):
	change = False
	new_window = [i for i in sequence]		 
	#err = np.array(predictions)-np.array(actual) # NOTE: when there is a missing value in actual, the fucntion of is_outlier() returns False.
	l = len(new_window)
	err = eliminate_trans_error(chps_ind, actual[l:], predictions)
	
	u = np.mean(err[:-1])
	s = np.std(err[:-1])
	
	if is_outliers(u,s, (predictions[-1]-new_window[-1])):
		new_window[-1] = new_window[-2]
		outlier_ind.append(len(predictions)-1)

	if len(outlier_ind) >= 3:	
		if (outlier_ind[-1] - outlier_ind[-2]) == 1 and (outlier_ind[-2] - outlier_ind[-3]) == 1 :
				new_window[-3:] = actual[-3:]
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

def data_preprocess(thr, data, MAX):
	wraps = list()
	for i in range(len(data)-1):
		if data[i+1] - data[i] < 0 and rela_diff(data[i], data[i+1], MAX) < thr:
			wraps.append(i+1)
	for _, i in enumerate(wraps):
		for t in range(i, len(data)):
			data[t] = data[t] + MAX
	return wraps

def pre_processing(sequence, MAX):
	diff_data = difference(sequence, 1, MAX)
	diff_data = array(diff_data).reshape(-1, 1)
	scaler = preprocessing.MinMaxScaler()
	diff_data = scaler.fit_transform(diff_data) # scaling the input and output data to the range of (0,1)
	minimum = scaler.data_min_
	maximum = scaler.data_max_
	return diff_data, maximum, minimum
		
def one_time_forecast(sequence, predictions, MAX):
	diff_data, maximum, minimum = pre_processing(sequence, MAX)
	X = np.array(range(len(sequence)-1)).reshape(-1, 1) # for time
	y = np.array(diff_data)
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
	
	
def gp():
		for l in [5, 10, 15, 20, 25, 30]:
		#for l in [5]:
			f = open('../ipid_prediction/evaluate/online_analysis/*_global.res', 'w')
			with open('../ipid_prediction/Dataset/online_analysis/*_global.data.res', 'r') as filehandle:
				filecontents = filehandle.readlines()
				for line in filecontents:
					fields = line.split(",")
					if len(fields) < 2 : continue
					ip = fields[0]
					dataStr=fields[1]
					sequence = extract(dataStr)
					timeStr= fields[2]
					times = extract(timeStr)
					'''
					times = list()
					for i in range(len(sequence)):
						times.append(i)
					'''
					for i, v in enumerate(sequence):
						if v == -1:
							sequence[i] = math.nan
					vel = 0
					history, actual = sequence[30-l:30], sequence[30:]
					
					elps = list()
					chps_ind = list()
					predictions = list()
					outlier_ind = list()
					tem_actual = sequence[30-l:30]
					
					#for plot: filtered data
					#filter_data = filter_outliers02(True, history, 65536)
					#filter_data = fill_miss_values(filter_data)
					#for plot
					
					for i in range(len(actual)+1): # Attention: need to modify the actual data because of the outliers (Done!)			
						start = time.monotonic()
						MAX = 65536
						
						if containNAN(history):
							vel = computeIpidVelocityNan(history, list(range(len(history))), MAX)
						else:
							vel = computeIpidVelocity02(history, list(range(len(history))), MAX) # eliminate the outliers' impact
						
						if vel < 1000: thr = 15000 # experimentially specify the threshold
						else: thr = 30000
						
						if i > 1 and  alarm_turning_point(thr, tem_actual[-2], tem_actual[-1], MAX):
								chps_ind.append(i-2)
								chps_ind.append(i-1)
						if i == len(actual): break
						
						
						history = fill_miss_values(history) # base
						#history = linear_interpolate_miss_values(history)
						#history = fill_predicted_values(history, predictions)
						
						outliers = False
						#history = filter_outliers(outliers, thr, history, MAX, outlier_ind)
						history, change = filter_outliersv2(outliers, history, thr, MAX, tem_actual, outlier_ind)
						change = False
						if change: # once identify an change rather than an outlier, then update the previouse incorrect predictions
							tem_actual[-l:] = [i for i in history]
							extra_preds = list()
							n = 3 
							if len(predictions) <3:
								n = len(predictions)
							for j in range(n, 0, -1):
								data = tem_actual[-(l+j):-j]
								one_time_forecast(data, extra_preds, MAX)
								if extra_preds[-1] < 0: extra_preds[-1] = 0
							predictions[-n:] = extra_preds
						
						one_time_forecast(history, predictions, MAX)
						if predictions[-1] < 0: predictions[-1] = 0
						end = time.monotonic()
						elps.append(end-start)
						tem_actual.append(actual[i])
						history.append(actual[i])
						history.pop(0)
					# identify change points and then eliminate the error from the transformation at the restore.
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
					
					err = ' '.join(map(str, after_diff))
					
					smape = sMAPE02(chps_ind, actual, predictions)
					t = statistics.mean(elps)
					f.write(ip+',['+ err +'],'+str(smape)+','+str(t)+'\n')
			f.close()

def interpolate_miss_values(sliding_window):
	s = pd.Series(sliding_window)
	return (s.interpolate(method='polynomial', order = 2, limit_direction='both').values % 65536).tolist() # 'spline'
	#return (s.interpolate(method='linear', limit_direction='both').values % 65536).tolist() 

def linear_interpolate_miss_values(sliding_window):
	s = pd.Series(sliding_window)
	return (s.interpolate(method='linear', limit_direction='both').values % 65536).tolist() 
	#return (s.interpolate(method='spline', order = 2, limit_direction='both').values % 65536).tolist()
	#return (s.interpolate(method='pad', limit=2).values % 65536).tolist()
	
def fill_miss_values(data):
	#if math.isnan(data[0]): data[0] = data[1]
	s = pd.Series(data)
	s = s.interpolate(method='pad')
	return (s.interpolate(method='linear', limit_direction ='both').values % 65536).tolist()
	
def fill_predicted_values(data, predictions):
	if math.isnan(data[-1]): 
		data[-1] = int(predictions[-1])
	return data

def main():
	gp()
			
if __name__ == "__main__":
    # execute only if run as a script
    main()


