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
import matplotlib as mpl
from matplotlib.animation import FuncAnimation
from random import randrange
import seaborn as sns
import matplotlib as mpl

cols = sns.color_palette("colorblind")
sns.set_theme(style="darkgrid")

mpl.rcParams['figure.dpi'] = 200
plt.rcParams["figure.figsize"] = (7,4.5)

lib = cdll.LoadLibrary("./ipid_pred_lib.so")
logging.basicConfig(level=logging.INFO, filename='grnn.test.log')
class go_string(Structure):
    _fields_ = [
        ("p", c_char_p),
        ("n", c_int)]

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
	
def find_sigma(train):
    	train = asarray(train)
    	data = np.concatenate((train[0, :-1], train[:, -1]), axis=None)
    	n = len(data)
    	diff = array([data[i+1]-data[i] for i in range(len(data)-1)])
    	return max(abs(diff))/sqrt(2*n)
    	

def real_time_forecasting(sequence, history, n_hold_out, maximum, minimum, MAX):
	#train, hold_out = history[:-n_hold_out], history[-n_hold_out:] # difference data
	sigma = walk_forward_validation(sequence, history, n_hold_out, maximum, minimum, MAX)
	#retrain a GRNN model
	pred = [history[-1,1:]]
	y_pred = train_and_predict(history, pred, sigma)
	return y_pred

def estimate_gaussian_error(sequence, diff_data, n_hold_out, n_step, sigma, maximum, minimum, MAX):
	history = reshape_inputs(diff_data, n_step)
	train, test = train_test_split(history, n_hold_out)
	X_train, y_train = train[:, :-1], train[:, -1] # y_train shape: 1D array
	X_test, y_test = test[:, :-1], test[:, -1]
	y_train = y_train.reshape(-1, 1)
	nw = algorithms.GRNN(std=sigma, verbose=False)
	nw.train(X_train, y_train)
	y_pred = nw.predict(X_test)
	y_pred = denormalize(y_pred, maximum, minimum)
	actual = sequence[-n_hold_out:]
	prediction = correct(sequence,y_pred, MAX)
	err = array(actual) - array(prediction)
	u = np.mean(err)
	s = np.std(err)
	pred = [history[-1,1:]]
	y_pred = train_and_predict(history, pred, sigma)
	return u, s, y_pred
	

def real_time_forecasting02(sequence, diff_data, n_steps, n_hold_out, maximum, minimum, MAX):
	#train, hold_out = history[:-n_hold_out], history[-n_hold_out:] # difference data
	n_step, sigma = walk_forward_validation02(sequence, diff_data, n_steps, n_hold_out, maximum, minimum, MAX)
	#u, s, y_pred = estimate_gaussian_error(sequence, diff_data, n_hold_out, n_step, sigma, maximum, minimum, MAX)
	#retrain a GRNN model
	#print(n_step, sigma)
	history = reshape_inputs(diff_data, n_step)
	pred = [history[-1,1:]]
	y_pred = train_and_predict(history, pred, sigma)
	return y_pred
	
def real_time_forecasting_rem(base_data, restore_data, history, n_hold_out, maximum, minimum, MAX):
	#train, hold_out = history[:-n_hold_out], history[-n_hold_out:] # difference data
	sigma = walk_forward_validation_rem(base_data, restore_data, history, n_hold_out, maximum, minimum, MAX)
	#retrain a GRNN model
	#pred = [history[-1,1:]]
	#y_pred = train_and_predict(history, pred, sigma)
	return sigma
	
def online_training(raw_data, data, n_steps, n_test, maximum, minimum):
	y_pred = list()
	# split dataset
	train, test = train_test_split(data, n_test)
	# seed history with training dataset
	
	history = [x for x in train]
	
	# step over each time-step in the test set
	for i in range(len(test)):
		# split test row into input and output columns
		X_test, y_test = test[i, :-1], test[i, -1]
		# fit model on history and make a prediction
		sigma = find_sigma(history)
		#print('sigma %.3f' %sigma)
		yhat = forecast(history, X_test, sigma)
		# store forecast in list of predictions
		y_pred.append(yhat)
		# add actual observation to history for the next loop
		history.append(test[i])
		history.pop(0)
		
	y_pred = array(y_pred)
	y_pred = denormalize(y_pred, maximum, minimum)
	actual = raw_data[-n_test:]
	prediction = correct(raw_data,y_pred)
	#print(actual)
	#print(prediction)

	diff = np.array(prediction) - np.array(actual)
	#print(-diff) # residual forecast error
	mae = np.mean(abs(diff))
	print('Test MAE: %.3f' % mae)
	#rmse = np.mean(diff**2)**.5
	#print('Test RMSE: %.3f' % rmse)
	#mape = np.mean(np.abs(diff)/np.array(actual))
	#print('Test MAPE: %.3f' % mape)
	smape = sMAPE(actual, prediction)
	print('Test sMAPE: %.3f' % smape)
	
	

def forecast(train, X_test, sigma):
	train = asarray(train)
	# split into input and output columns
	X_train, y_train = train[:, :-1], train[:, -1]
	nw = algorithms.GRNN(std=sigma, verbose=False)
	nw.train(X_train, y_train)
	y_pred = nw.predict([X_test])
	return y_pred[0]

	
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

def walk_forward_validation02(sequence, diff_data, n_steps, n_hold_out, maximum, minimum, MAX):
	errors = []
	sigmas = []
	for n_step in n_steps:
		history = reshape_inputs(diff_data, n_step)
		train, test = train_test_split(history, n_hold_out)
		if len(train) == 0: continue
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
			
			#y_pred = denormalize(y_pred, maximum, minimum)
			#actual = sequence[-n_hold_out:]
			#prediction = correct(sequence,y_pred, MAX)
			#diff = np.array(prediction) - np.array(actual)
			
			y_test = y_test.reshape(-1)
			y_pred = y_pred.reshape(-1)
			diff = np.array(y_pred) - np.array(y_test)
			#mae = np.mean(abs(diff))
			#rmse = sqrt(mean_squared_error(actual, prediction))
			rmse = np.mean(array(diff)**2)**.5
			if math.isnan(rmse): 
				sigma = sigma + 0.1
				continue
			errs.append(rmse)
			sigs.append(sigma)
			sigma = sigma + 0.1
		if len(errs) == 0:
			print('NAN prediction errors:', sequence)
			errors.append(math.nan)
			sigmas.append(0.1)
			continue
		min_index = min( (v, i) for i, v in enumerate(errs) )[1]
		errors.append(errs[min_index])
		sigmas.append(sigs[min_index])
	
	min_index = min( (v, i) for i, v in enumerate(errors) )[1]
	sigma = sigmas[min_index]
	n_step = n_steps[min_index]
	return n_step, sigma

	
def walk_forward_validation_rem(base_data, restore_data, history, n_hold_out, maximum, minimum, MAX):
	n_hold_out = int(history.shape[0] * 0.3)
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
		#y_test = y_test.reshape(-1)
		#y_pred = y_pred.reshape(-1)
		#diff = y_pred - y_test
		#print('y_pred: ', y_pred)
		#print('X_test: ', X_test)
		
		y_pred = denormalize(y_pred, maximum, minimum)
		actual =restore_data[-n_hold_out:]
		prediction = correct02(base_data,y_pred, MAX)
		diff = np.array(prediction) - np.array(actual)
		
		#mae = np.mean(abs(diff))
		#rmse = sqrt(mean_squared_error(actual, prediction))
		rmse = np.mean(array(diff)**2)**.5
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

	
def train_and_predict(data, pred, sigma):
	X_train, y_train = data[:, :-1], data[:, -1]
	y_train = y_train.reshape(-1, 1)
	#y_test = y_test.reshape(-1, 1)
	nw = algorithms.GRNN(std=sigma, verbose=False)
	nw.train(X_train, y_train)
	#predict the value in the three seconds
	y_pred = nw.predict(pred)
	return y_pred
	
def test_predict(history, maximum, minimum):
	raw_pred = [58529, 59959, 61865, 63595]
	pred = difference(raw_pred, 1)
	pred = array(pred).reshape(1,-1)
	pred = (pred-minimum)/(maximum-minimum)
	y_pred = train_and_predict(history, pred)
	y_pred = denormalize(y_pred, maximum, minimum)
	prediction = (y_pred[0] + raw_pred[-1] - 65536)%65536
	print(prediction)

def pre_processing(sequence, MAX):
	#history = filter_outliers(history, MAX)
	diff_data = difference(sequence, 1, MAX)
	diff_data = array(diff_data).reshape(-1, 1)
	scaler = preprocessing.MinMaxScaler()
	diff_data = scaler.fit_transform(diff_data) # scaling the input and output data to the range of (0,1)
	minimum = scaler.data_min_
	maximum = scaler.data_max_
	return diff_data, maximum, minimum

def pre_processing02(sequence):
	diff_data = array(difference(sequence, 1)).reshape(-1, 1)
	scaler = preprocessing.StandardScaler()
	diff_data = scaler.fit_transform(diff_data) 
	return diff_data, scaler

def reshape_inputs(diff_data, n_steps):
	num = len(diff_data)
	values = asarray(diff_data).reshape((num, 1))
	# transform the time series data into supervised learning
	data = series_to_supervised(values, n_in=n_steps)
	return data
	
def probe(target):
	b = go_string(c_char_p(target), len(target))
	a = lib.probe(b)
	return a
	
def one_time_forecast(sequence, predictions, n_steps, n_hold_out, MAX):
	#start = time.monotonic()
	diff_data, maximum, minimum = pre_processing(sequence, MAX)
	
	#data = reshape_inputs(diff_data, n_steps)
	#y_pred = real_time_forecasting(sequence, data, n_hold_out, maximum, minimum, MAX)
	
	y_pred = real_time_forecasting02(sequence, diff_data, n_steps, n_hold_out, maximum, minimum, MAX)
	y_pred = denormalize(y_pred, maximum, minimum)
	prediction = (y_pred[0] + sequence[-1])%MAX
	predictions.append(prediction[0])
	#end = time.monotonic()
	#elapsed = end-start
	#return elapsed
	#print("Time elapsed during the one-time forecast:", end - start)

def one_time_forecast_rem(sequence, predictions, n_steps, n_hold_out, MAX):
	diff_data, maximum, minimum = pre_processing(sequence, MAX)
	#print('diff_data: ', diff_data)
	data = reshape_inputs(diff_data, n_steps)
	base_data, restore_data = obtain_restore_data(sequence, diff_data)
	sigma = real_time_forecasting_rem(base_data, restore_data, data, n_hold_out, maximum, minimum, MAX)
	diff_data = diff_data.flatten()
	'''pred = diff_data[-1]+diff_data[-2]+diff_data[-3] 
	if math.isnan(pred): 
		predictions.append(math.nan)
		return'''
	#print(math.isnan(diff_data[-3]+[math.nan])) == True
	pred = array([diff_data[-3], diff_data[-2], diff_data[-1]])
	pred = [pred]
	y_pred = train_and_predict(data, pred, sigma)
	y_pred = denormalize(y_pred, maximum, minimum)
	prediction = (y_pred[0] + sequence[-1])%65536
	predictions.append(prediction[0])
	
		
def offline_forecast(data):
	y_pred = list()
	# split dataset
	train, test = train_test_split(data, n_test)
	# seed history with training dataset
	
	history = [x for x in train]
	
	# step over each time-step in the test set
	for i in range(len(test)):
		# split test row into input and output columns
		X_test, y_test = test[i, :-1], test[i, -1]
		# fit model on history and make a prediction
		sigma = find_sigma(history)
		#print('sigma %.3f' %sigma)
		yhat = forecast(history, X_test, sigma)
		# store forecast in list of predictions
		y_pred.append(yhat)
		# add actual observation to history for the next loop
		history.append(test[i])
		history.pop(0)
		
	y_pred = array(y_pred)
	y_pred = denormalize(y_pred, maximum, minimum)
	actual = raw_data[-n_test:]
	prediction = correct(raw_data,y_pred)
	#print(actual)
	#print(prediction)

	diff = np.array(prediction) - np.array(actual)
	#print(-diff) # residual forecast error
	mae = np.mean(abs(diff))
	print('Test MAE: %.3f' % mae)
	#rmse = np.mean(diff**2)**.5
	#print('Test RMSE: %.3f' % rmse)
	#mape = np.mean(np.abs(diff)/np.array(actual))
	#print('Test MAPE: %.3f' % mape)
	smape = sMAPE(actual, prediction)
	print('Test sMAPE: %.3f' % smape)
	

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
	
def isNormal(data, MAX):
	for i in range(0, len(data)-1):
		if data[i+1]-data[i] < 0:
			if rela_diff(data[i], data[i+1], MAX) > 10000:
				return False
	return True


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
	
def hole_loss(ids, times, loss_rate):
	new_ids = []
	new_times = []
	n = int(len(ids)*loss_rate)
	start_point = randrange(30, len(ids)-n-3)
	
	for i in range(len(ids)):
		if i >= start_point and i < start_point + n:
			continue
		new_ids.append(ids[i])
		new_times.append(times[i])
	return new_ids, new_times

def random_loss(ids, times, loss_rate):
	n = int(len(ids) * loss_rate)
	new_ids = []
	new_times = []
	rands = random.sample(range(30, len(ids)), n)
	for i in range(len(ids)):
		if i in rands:
			new_ids.append(-1)
			new_times.append(times[i])
			continue
		new_ids.append(ids[i])
		new_times.append(times[i])

	return new_ids, new_times

def generate_changes():
	#for d in ['v(0-100)', 'v(100-500)', 'v(500-1200)', 'v(1200+)']:
		filecontents = None
		f = open('../ipid_prediction/Dataset/validation_data/icmp_global.changes.data', 'w')
		with open('../ipid_prediction/Dataset/validation_data/icmp_global.data', 'r') as filehandle:
			filecontents = filehandle.readlines()
		#indices = random.sample(range(0, len(filecontents)), int(len(filecontents)*0.1))
		#print(indices)
		for i, line in enumerate(filecontents):
			fields = line.split(",")
			if len(fields) < 3 : continue
			ip = fields[0]
			idStr=fields[1]
			timeStr = fields[2]
			ids = extract(idStr)
			times = extract(timeStr)
			MAX = 65536
			new_ids, new_times = hole_loss(ids, times, 0.10)
			f.write(ip+','+'['+' '.join(map(str, new_ids))+']'+',['+' '.join(map(str, new_times))+']'+'\n')
		f.close()

def generate_random_loss_data():
	#for d in ['v(0-100)', 'v(100-500)', 'v(500-1200)', 'v(1200+)']:
		filecontents = None
		f = open('../ipid_prediction/Dataset/validation_data/icmp_global.miss.data', 'w')
		with open('../ipid_prediction/Dataset/validation_data/icmp_global.data', 'r') as filehandle:
			filecontents = filehandle.readlines()
			for i, line in enumerate(filecontents):
				fields = line.split(",")
				if len(fields) < 3 : continue
				#ns = fields[1]
				ip = fields[0]
				idStr=fields[1]
				timeStr = fields[2]
				ids = extract(idStr)
				times = extract(timeStr)
				ids, times = random_loss(ids, times, loss_rate = 0.05)
				ids_str = ' '.join(map(str, ids))
				times_str = ' '.join(map(str, times))
				f.write(ip+',['+ids_str+']'+',['+times_str+']'+'\n')
		f.close()

def generate_data_extra():
	f = open('../ipid_prediction/evaluate/global.vel(100-500).data', 'w')
	with open('../training_data/global.vel(100-500).data', 'r') as filehandle:
		filecontents = filehandle.readlines()
	indices = random.sample(range(0, len(filecontents)), 200)
	for i, line in enumerate(filecontents):
		fields = line.split(",")
		if len(fields) < 3 : continue
		ip = fields[0]
		dataStr=fields[1]
		sequence = extract(dataStr)
		sequence = sequence[0:60]
		if i in indices:
			f.write(ip+','+'['+' '.join(map(str, sequence))+']'+'\n')
	f.close()
		
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

def plot_outliers_changes():
	sns.set(rc={'figure.figsize':(6,3)})
	a = list()
	b = list()
	with open('../training_data/test.data', 'r') as filehandle:
		filecontents = filehandle.readlines()
		for i, line in enumerate(filecontents):
			fields = line.split(",")
			if len(fields) < 2 : continue
			ip = fields[0]
			print(ip)
			dataStr=fields[1]
			sequence = extract(dataStr)
			if i == 0: a = np.array(sequence[46:60])
			if i == 1: b = np.array(sequence[18:32])
			if i == 1: break
	print(len(a), len(b))
	df = pd.DataFrame({'a':a, 'b':b})
	g = sns.lineplot(data=df)
	g.set_xticks(range(len(df)))
	#g.set_xlabel('Received time (i-th second)', fontsize=10)
	#g.set_ylabel('IP ID values', fontsize=10)
	plt.savefig('../images/outliers_changes.pdf')
	#plt.show()					

def grnn():
	
		for l in [5, 10, 15, 20, 25, 30]:
		#for l in [30]:
			f = open('../ipid_prediction/evaluate/online_analysis/*_global.res', 'w') #w('+str(l)+')
			with open('../ipid_prediction/Dataset/online_analysis/*_global.data', 'r') as filehandle:
				filecontents = filehandle.readlines()
				for line in filecontents:
					fields = line.split(",")
					if len(fields) < 2 : continue
					ip = fields[0]
					dataStr=fields[1]
					sequence = extract(dataStr)
					
					for i, v in enumerate(sequence):
						if v == -1:
							sequence[i] = math.nan
					
					vel = 0
					n_steps = [2, 3, 4, 5, 6]
					history, actual = sequence[30-l:30], sequence[30:]
					n_hold_out = int(len(history)*3/10)
					elps = list()
					chps_ind = list()
					predictions = list()
					outlier_ind = list()
					tem_actual = sequence[30-l:30]
					new_window = list()
					for i in range(len(actual)+1): # Attention: need to modify the actual data because of the outliers (Done!)			
						start = time.monotonic()
						MAX = 65536
						
						if containNAN(history):
							vel = computeIpidVelocitySeg(history, list(range(len(history))), MAX)
						else:
							vel = computeIpidVelocity02(history, list(range(len(history))), MAX) # eliminate the outliers' impact
						
						if vel < 1000: thr = 15000 # experimentially specify the threshold
						else: thr = 30000
						
						if i > 1 and  alarm_turning_point(thr, tem_actual[-2], tem_actual[-1], MAX):
								chps_ind.append(i-2)
								chps_ind.append(i-1)
						if i == len(actual): break
						
						history = fill_miss_values(history) # base.res, try linear_interpolate_miss_values
						#new_window = linear_interpolate_miss_values(new_window)
						
						outliers = False
						change = False
						history, change = filter_outliersv2(outliers, history, thr, MAX, tem_actual, outlier_ind)
						if change:
							tem_actual[-l:] = [i for i in history]
							extra_preds = list()
							n = 3 
							if len(predictions) <3:
								n = len(predictions)
							for j in range(n, 0, -1):
								data = tem_actual[-(l+j):-j]
								one_time_forecast(data, extra_preds, n_steps, n_hold_out, MAX)
								if extra_preds[-1] < 0: extra_preds[-1] = 0
							predictions[-n:] = extra_preds
						
						one_time_forecast(history, predictions, n_steps, n_hold_out, MAX)
						if predictions[-1] < 0: predictions[-1] = 0
						
						end = time.monotonic()
						elps.append(end-start)
						tem_actual.append(actual[i])
						history.append(actual[i])
						history.pop(0)
					
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
	grnn()
		
if __name__ == "__main__":
    # execute only if run as a script
    main()


