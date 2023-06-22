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
#from grnn02 import one_time_forecast02
from scipy.stats import norm
import random
import csv
import logging
import matplotlib as mpl
from matplotlib.animation import FuncAnimation
from random import randrange

#from sknn.mlp import Regressor, Layer
import matplotlib as mpl
import warnings
warnings.filterwarnings("ignore")

'''
sigma = 0.1  # Set the sigma value
mlp = Regressor(
    layers=[
        Layer('Gaussian', units=10, sigma=sigma),
        Layer('Linear')],
    learning_rate=0.01,
    n_iter=100)
'''  
mpl.rcParams['figure.dpi'] = 200
plt.rcParams["figure.figsize"] = (7, 4.5)

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
        # dur = float(times[i+1]-times[i])/1000000000.0 #unit: ID/s
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
    if len(id_segment) >= 3:  # without NAN
        vel = computeIpidVelocity(id_segment, time_segment, MAX)
        vels.append(vel)
    if len(vels) == 2 and len(id_segment) > len(ids)/2:
        return vels[1]
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
        if math.isnan(diff_data[i-3]+diff_data[i-2]+diff_data[i-1]+diff_data[i]):
            continue
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
        if math.isnan(v):
            continue
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
        if (actual[i] + predictions[i]) != 0:
            res.append(
                2 * abs(predictions[i]-actual[i]) / (actual[i] + predictions[i]))
        else:
            res.append(0)
    after_res = list()
    for v in res:
        if math.isnan(v):
            continue
        after_res.append(v)
    return np.mean(after_res)


def find_sigma(train):
    train = asarray(train)
    data = np.concatenate((train[0, :-1], train[:, -1]), axis=None)
    n = len(data)
    diff = array([data[i+1]-data[i] for i in range(len(data)-1)])
    return max(abs(diff))/sqrt(2*n)


def real_time_forecasting(sequence, history, n_hold_out, maximum, minimum, MAX):
    # train, hold_out = history[:-n_hold_out], history[-n_hold_out:] # difference data
    sigma = walk_forward_validation(
        sequence, history, n_hold_out, maximum, minimum, MAX)
    # retrain a GRNN model
    pred = [history[-1, 1:]]
    y_pred = train_and_predict(history, pred, sigma)
    return y_pred


def estimate_gaussian_error(sequence, diff_data, n_hold_out, n_step, sigma, maximum, minimum, MAX):
    history = reshape_inputs(diff_data, n_step)
    train, test = train_test_split(history, n_hold_out)
    X_train, y_train = train[:, :-1], train[:, -1]  # y_train shape: 1D array
    X_test, y_test = test[:, :-1], test[:, -1]
    y_train = y_train.reshape(-1, 1)
    nw = algorithms.GRNN(std=sigma, verbose=False)
    nw.train(X_train, y_train)
    y_pred = nw.predict(X_test)
    y_pred = denormalize(y_pred, maximum, minimum)
    actual = sequence[-n_hold_out:]
    prediction = correct(sequence, y_pred, MAX)
    err = array(actual) - array(prediction)
    u = np.mean(err)
    s = np.std(err)
    pred = [history[-1, 1:]]
    y_pred = train_and_predict(history, pred, sigma)
    return u, s, y_pred


def real_time_forecasting02(sequence, diff_data, n_step, n_hold_out, sigma, maximum, minimum, MAX):

    #n_step, sigma = walk_forward_validation02(sequence, diff_data, n_steps, n_hold_out, maximum, minimum, MAX)

    history = reshape_inputs(diff_data, n_step)
    pred = [history[-1, 1:]]
    y_pred = train_and_predict(history, pred, sigma)
    return y_pred


def real_time_forecasting_rem(base_data, restore_data, history, n_hold_out, maximum, minimum, MAX):
    # train, hold_out = history[:-n_hold_out], history[-n_hold_out:] # difference data
    sigma = walk_forward_validation_rem(
        base_data, restore_data, history, n_hold_out, maximum, minimum, MAX)
    # retrain a GRNN model
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
    prediction = correct(raw_data, y_pred)
    # print(actual)
    # print(prediction)

    diff = np.array(prediction) - np.array(actual)
    # print(-diff) # residual forecast error
    mae = np.mean(abs(diff))
    print('Test MAE: %.3f' % mae)
    #rmse = np.mean(diff**2)**.5
    #print('Test RMSE: %.3f' % rmse)
    #mape = np.mean(np.abs(diff)/np.array(actual))
    #print('Test MAPE: %.3f' % mape)
    smape = sMAPE(actual, prediction)
    print('Test sMAPE: %.3f' % smape)
    '''pyplot.plot(actual, label='Expected')
	pyplot.plot(prediction, label='Predicted')
	pyplot.legend()
	pyplot.show()'''


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
    X_train, y_train = train[:, :-1], train[:, -1]  # y_train shape: 1D array
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
        prediction = correct(sequence, y_pred, MAX)
        #diff = np.array(prediction) - np.array(actual)
        #mae = np.mean(abs(diff))
        rmse = sqrt(mean_squared_error(actual, prediction))
        if math.isnan(rmse):
            sigma = sigma + 0.1
            continue
        errs.append(rmse)
        sigs.append(sigma)
        sigma = sigma + 0.1
    if len(errs) == 0:
        return 0.1
    min_index = min((v, i) for i, v in enumerate(errs))[1]
    sigma = sigs[min_index]
    return sigma


def walk_forward_validation02(sequence, diff_data, n_steps, n_hold_out, maximum, minimum, MAX):
    errors = []
    sigmas = []
    for n_step in n_steps:
        history = reshape_inputs(diff_data, n_step)
        train, test = train_test_split(history, n_hold_out)
        if len(train) == 0:
            continue
        # y_train shape: 1D array
        X_train, y_train = train[:, :-1], train[:, -1]
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
        min_index = min((v, i) for i, v in enumerate(errs))[1]
        errors.append(errs[min_index])
        sigmas.append(sigs[min_index])

    min_index = min((v, i) for i, v in enumerate(errors))[1]
    sigma = sigmas[min_index]
    n_step = n_steps[min_index]
    return n_step, sigma


def walk_forward_validation_rem(base_data, restore_data, history, n_hold_out, maximum, minimum, MAX):
    n_hold_out = int(history.shape[0] * 0.3)
    train, test = train_test_split(history, n_hold_out)
    X_train, y_train = train[:, :-1], train[:, -1]  # y_train shape: 1D array
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
        actual = restore_data[-n_hold_out:]
        prediction = correct02(base_data, y_pred, MAX)
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
    if len(errs) == 0:
        return 0.1
    min_index = min((v, i) for i, v in enumerate(errs))[1]
    sigma = sigs[min_index]
    return sigma


def train_and_predict(data, pred, sigma):
    X_train, y_train = data[:, :-1], data[:, -1]
    y_train = y_train.reshape(-1, 1)
    #y_test = y_test.reshape(-1, 1)
    nw = algorithms.GRNN(std=sigma, verbose=False)
    nw.train(X_train, y_train)
    
    # predict the value in the three seconds
    y_pred = nw.predict(pred)
    return y_pred


def test_predict(history, maximum, minimum):
    raw_pred = [58529, 59959, 61865, 63595]
    pred = difference(raw_pred, 1)
    pred = array(pred).reshape(1, -1)
    pred = (pred-minimum)/(maximum-minimum)
    y_pred = train_and_predict(history, pred)
    y_pred = denormalize(y_pred, maximum, minimum)
    prediction = (y_pred[0] + raw_pred[-1] - 65536) % 65536
    print(prediction)


def pre_processing(sequence, MAX):
    #history = filter_outliers(history, MAX)
    diff_data = difference(sequence, 1, MAX)
    diff_data = array(diff_data).reshape(-1, 1)
    scaler = preprocessing.MinMaxScaler()
    # scaling the input and output data to the range of (0,1)
    diff_data = scaler.fit_transform(diff_data)
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


def one_time_forecast(sequence, predictions, n_steps, n_hold_out, sigma, MAX):
    
    diff_data, maximum, minimum = pre_processing(sequence, MAX)
    y_pred = real_time_forecasting02(
        sequence, diff_data, n_steps, n_hold_out, sigma, maximum, minimum, MAX)
    y_pred = denormalize(y_pred, maximum, minimum)
    prediction = (y_pred[0] + sequence[-1]) % MAX
    predictions.append(prediction[0])
    
    


def one_time_forecast_rem(sequence, predictions, n_steps, n_hold_out, MAX):
    diff_data, maximum, minimum = pre_processing(sequence, MAX)
    #print('diff_data: ', diff_data)
    data = reshape_inputs(diff_data, n_steps)
    base_data, restore_data = obtain_restore_data(sequence, diff_data)
    sigma = real_time_forecasting_rem(
        base_data, restore_data, data, n_hold_out, maximum, minimum, MAX)
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
    prediction = (y_pred[0] + sequence[-1]) % 65536
    predictions.append(prediction[0])


def single_ip_forecast_old(ipStr):
    # verify if this ip is reachable
    ip = bytes(ipStr, 'utf-8')  # Go source code is always utf-8.
    count = 0
    for i in range(3):
        ipid = probe(ip)
        if ipid == -1:
            count = count+1
    if count == 3:
        mutex.acquire()
        dataset['ip'].append(ipStr)
        dataset['mae'].append(None)
        dataset['smape'].append(None)
        mutex.release()
        return
    sliding_window = list()
    wlth = 30
    plth = 30
    actual = list()
    predictions = list()

    start = time.monotonic()
    while True:
        end = time.monotonic()
        if (end-start) >= 120:
            break
        ipid = probe(ip)
        #ipid = test_data.pop(0)
        if ipid == -1:  # packet loss
            if len(sliding_window) == wlth and len(predictions) > 0:
                predictions.pop(-1)
            sliding_window = list()
            continue
        sliding_window.append(ipid)
        if len(sliding_window) == wlth+1:
            actual.append(sliding_window[-1])
            sliding_window.pop(0)
        if len(predictions) == plth:
            break
        if len(sliding_window) == wlth:
            sequence = [x for x in sliding_window]
            t = threading.Thread(target=one_time_forecast,
                                 args=(sequence, predictions))
            t.start()
        time.sleep(1)
    if len(actual) == 0 or len(predictions) == 0 or len(actual) != len(predictions):
        mutex.acquire()
        dataset['ip'].append(ipStr)
        dataset['mae'].append(None)
        dataset['smape'].append(None)
        mutex.release()
        return
    diff = np.array(predictions) - np.array(actual)
    mae = np.mean(abs(diff))
    smape = sMAPE(actual, predictions)
    mutex.acquire()
    dataset['ip'].append(ipStr)
    dataset['mae'].append(mae)
    dataset['smape'].append(smape)
    mutex.release()


def single_ip_forecast(ipStr):
    # verify if this ip is reachable
    ip = bytes(ipStr, 'utf-8')  # Go source code is always utf-8.
    count = 0
    for i in range(3):
        ipid = probe(ip)
        if ipid == -1:
            count = count+1
    if count == 3:
        dataset['ip'].append(ipStr)
        dataset['rmse'].append(None)
        dataset['smape'].append(None)
        return
    sliding_window = list()
    wlth = 30
    plth = 30
    #n_steps, n_hold_out = 3, 9
    n_steps = [3, 4, 5, 6]
    n_hold_out = 9
    actual = list()
    predictions = list()
    chps_ind = list()
    while True:
        start = time.monotonic()
        ipid = probe(ip)
        if ipid == -1:
            ipid = math.nan
        sliding_window.append(ipid)
        with open('./ipid_data.csv', 'a') as csv_file:
            csv_writer = csv.DictWriter(
                csv_file, fieldnames=['actual', 'prediction'])
            if len(predictions) == 0:
                prediction = math.nan
            else:
                prediction = round(predictions[-1])
            info = {
                'actual': sliding_window[-1],
                'prediction': prediction
            }
            csv_writer.writerow(info)
        if len(sliding_window) == wlth+1:
            actual.append(sliding_window[-1])
            sliding_window.pop(0)
        if len(predictions) == plth:
            break
        if len(sliding_window) == wlth:
            count = 0
            for x in sliding_window:
                if math.isnan(x):
                    count = count + 1
            if count/wlth > 0.1:
                break

            MAX = 65536
            #num = count_ipid_wraps(sliding_window)
            #if num > 0 and max(sliding_window) < 32768 : MAX = 32768

            outlier = True
            if containNAN(sliding_window):
                vel = computeIpidVelocitySeg(
                    sliding_window, list(range(len(sliding_window))), MAX)
            else:
                vel = computeIpidVelocity02(sliding_window, list(
                    range(len(sliding_window))), MAX)  # eliminate the outliers' impact
            if vel > 10000:
                outlier = False  # For high fluctuating

            sliding_window = filter_outliers02(outlier, sliding_window, MAX)

            if len(predictions) > 0 and math.isnan(sliding_window[-1]):
                actual[-1] = math.nan
            if len(predictions) > 0 and math.isnan(sliding_window[-2]):
                actual[i-2] = math.nan
            if len(predictions) > 0 and alarm_change_point(vel, sliding_window[-2], sliding_window[-1], MAX):
                chps_ind.append(len(predictions)-1)
            new_window = fill_miss_values(sliding_window)
            t = threading.Thread(target=one_time_forecast, args=(
                new_window, predictions, n_steps, n_hold_out, MAX))
            t.start()
        end = time.monotonic()
        elapsed = end-start
        time.sleep(1-elapsed)
    if len(predictions) != plth:
        dataset['ip'].append(ipStr)
        dataset['rmse'].append(None)
        dataset['smape'].append(None)
        return
    predictions = [round(i) for i in predictions]
    print('predictions: ', ip, predictions)
    print('actual: ', ip, actual)
    #diff = np.array(predictions) - np.array(actual)
    diff = eliminate_trans_error(chps_ind, actual, predictions)
    after_diff = list()
    for v in diff:
        if math.isnan(v):
            continue
        after_diff.append(v)
    if len(after_diff) < plth * 0.7:
        dataset['ip'].append(ipStr)
        dataset['rmse'].append(None)
        dataset['smape'].append(None)
        return
    #mae = np.mean(abs(array(after_diff)))
    rmse = np.mean(array(after_diff)**2)**.5
    #smape = sMAPE(actual, predictions)
    smape = sMAPE02(chps_ind, actual, predictions)
    dataset['ip'].append(ipStr)
    dataset['rmse'].append(rmse)
    dataset['smape'].append(smape)


def group_ips_measure(ips):
    for ip in ips:
        single_ip_forecast(ip)


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
    prediction = correct(raw_data, y_pred)
    # print(actual)
    # print(prediction)

    diff = np.array(prediction) - np.array(actual)
    # print(-diff) # residual forecast error
    mae = np.mean(abs(diff))
    print('Test MAE: %.3f' % mae)
    #rmse = np.mean(diff**2)**.5
    #print('Test RMSE: %.3f' % rmse)
    #mape = np.mean(np.abs(diff)/np.array(actual))
    #print('Test MAPE: %.3f' % mape)
    smape = sMAPE(actual, prediction)
    print('Test sMAPE: %.3f' % smape)
    '''pyplot.plot(actual, label='Expected')
	pyplot.plot(prediction, label='Predicted')
	pyplot.legend()
	pyplot.show()'''


def filter_outliers_old(sequence, MAX):
    #scaler = preprocessing.MinMaxScaler()
    #diff_data = scaler.fit_transform(np.array(diff_data).reshape(-1, 1))
    #diff_data = diff_data.flatten()
    diff_data = difference(sequence, 1, MAX)
    sorted_data = sorted(diff_data)
    med_index = len(sorted_data) // 2
    med = np.median(sorted_data)
    g1, g2 = list(), list()
    if len(sorted_data) % 2 == 0:
        for i, d in enumerate(sorted_data):
            if i < med_index:
                g1.append(d)
            if i >= med_index:
                g2.append(d)
    else:
        for i, d in enumerate(sorted_data):
            if i < med_index:
                g1.append(d)
            if i > med_index:
                g2.append(d)
    q1 = np.median(g1)
    q3 = np.median(g2)
    for i in range(len(diff_data)):
        # i < q1 - 1.5 * (q3-q1), identify change points with too much noise or outliers
        if diff_data[i] > q3 + 1.5 * (q3-q1) and diff_data[i] > 10000:
            diff_data[i] = math.nan
    restore_data = list()
    restore_data.append(sequence[0])
    for i in range(len(diff_data)):
        restore_data.append((sequence[i] + diff_data[i]) % 65536)
    return restore_data


def filter_outliers02(outlier, sequence, MAX):
    new_window = [i for i in sequence]
    if not outlier:
        return new_window
    for i in range(0, len(new_window)-2):
        mini_window = [new_window[i], new_window[i+1], new_window[i+2]]
        if containNAN(mini_window):
            continue
        delta1 = rela_diff(new_window[i], new_window[i+1], MAX)
        delta2 = rela_diff(new_window[i+1], new_window[i+2], MAX)
        if delta1 > 10000 or delta2 > 10000:  # suitable for two consecutive outliers
            mini_window = array(mini_window)
            med = np.median(mini_window)
            mini_window = abs(mini_window - med)
            max_index = max((v, i) for i, v in enumerate(mini_window))[1]
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
    if not outlier:
        return new_window
    index = 0
    for i in range(index, len(new_window)-2):
        mini_window = [new_window[i], new_window[i+1], new_window[i+2]]
        if containNAN(mini_window):
            continue
        delta1 = rela_diff(new_window[i], new_window[i+1], MAX)
        delta2 = rela_diff(new_window[i+1], new_window[i+2], MAX)

        if delta1 > thr or delta2 > thr:  # suitable for two consecutive outliers
            mini_window = array(mini_window)
            med = np.median(mini_window)
            mini_window = abs(mini_window - med)
            max_index = max((v, i) for i, v in enumerate(mini_window))[1]
            if i+max_index == 0:  # process the outliers detected
                new_window[i+max_index] = new_window[1]
            else:
                new_window[i+max_index] = new_window[i+max_index-1]
            indices.append(i+max_index)
            if len(indices) >= 3:  # if the number of consecutive outliers is more than three, then the change will be viewed as normal
                if indices[-2]-indices[-3] == 1 and indices[-1]-indices[-2] == 1:
                    new_window = [i for i in sequence]
                    index = indices[-1] + 1
    return new_window


def filter_outliers_mini(outlier, sequence, MAX):
    new_window = sequence[-3:]
    if not outlier:
        return
    delta1 = rela_diff(new_window[0], new_window[1], MAX)
    delta2 = rela_diff(new_window[1], new_window[2], MAX)
    if delta1 > 10000 or delta2 > 10000:  # suitable for two consecutive outliers
        mini_window = array(new_window)
        med = np.median(mini_window)
        mini_window = abs(mini_window - med)
        max_index = max((v, i) for i, v in enumerate(mini_window))[1]
        sequence[-3+max_index] = math.nan


def filter_outliersv2(outlier, sequence, thr, MAX, actual, outlier_ind):
    change = False
    new_window = [i for i in sequence]
    if not outlier:
        return new_window, change
    if len(actual) == len(new_window):
        n = 0
    else:
        n = len(new_window)-3
    for i in range(n, len(new_window)-2):
        mini_window = [new_window[i], new_window[i+1], new_window[i+2]]
        if containNAN(mini_window):
            continue
        if alarm_turning_point(thr, mini_window[0], mini_window[1], MAX):
            mini_window[1] = (mini_window[1] + MAX)
        if alarm_turning_point(thr, mini_window[1], mini_window[2], MAX):
            mini_window[2] = (mini_window[2] + MAX)
        delta1 = rela_diff(mini_window[0], mini_window[1], MAX)
        delta2 = rela_diff(mini_window[1], mini_window[2], MAX)
        if delta1 > thr or delta2 > thr:  # suitable for two consecutive outliers
            mini_window = array(mini_window)
            med = np.median(mini_window)
            mini_window = abs(mini_window - med)
            max_index = max((v, i) for i, v in enumerate(mini_window))[1]

            if i+max_index == 0:  # process the outliers detected
                new_window[i+max_index] = new_window[1]
            else:
                new_window[i+max_index] = new_window[i+max_index-1]
            outlier_ind.append(len(actual)-len(new_window)+i+max_index)
            if len(outlier_ind) >= 3:
                if (outlier_ind[-1] - outlier_ind[-2]) == 1 and (outlier_ind[-2] - outlier_ind[-3]) == 1:
                    new_window[i] = actual[i+len(actual)-len(new_window)]
                    new_window[i+1] = actual[i+1+len(actual)-len(new_window)]
                    new_window[i+2] = actual[i+2+len(actual)-len(new_window)]
                    outlier_ind.clear()
                    change = True
    return new_window, change


def is_outliers(u, s, diff):
    v = (diff-u)/s
    if norm.cdf(v) > 0.98 or norm.cdf(v) < 0.02:  # p = 0.05
        return True
    return False


def filter_outliers_normal_distr(outlier, sequence, chps_ind, actual, predictions, outlier_ind):
    change = False
    new_window = [i for i in sequence]
    # err = np.array(predictions)-np.array(actual) # NOTE: when there is a missing value in actual, the fucntion of is_outlier() returns False.
    l = len(new_window)
    err = eliminate_trans_error(chps_ind, actual[l:], predictions)

    u = np.mean(err[:-1])
    s = np.std(err[:-1])

    if is_outliers(u, s, (predictions[-1]-new_window[-1])):
        new_window[-1] = new_window[-2]
        outlier_ind.append(len(predictions)-1)

    if len(outlier_ind) >= 3:
        if (outlier_ind[-1] - outlier_ind[-2]) == 1 and (outlier_ind[-2] - outlier_ind[-3]) == 1:
            new_window[-3:] = actual[-3:]
            outlier_ind.clear()
            change = True
    return new_window, change


def alarm_turning_point(thr, a1, a2, MAX):
    alarm = False
    delta = a2 - a1
    # a2-a1+MAX approximates to a2 (close to 1 in ideal)
    if delta < 0 and rela_diff(a1, a2, MAX) < thr:
        alarm = True
    return alarm


def cut_off_data():
    f = open('../ipid_prediction/Dataset/validation_data/icmp_global.data', 'w')
    #f = open('../training_data/test.noisy.res', 'w')
    elps = list()
    # global.50.data for measuring the time overhead
    with open('../training_data/global.data', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            fields = line.split(",")
            if len(fields) < 3:
                continue
            ip = fields[0]
            dataStr = fields[1]
            sequence = extract(dataStr)
            #sequence = sequence[-60:]
            sequence = sequence[0:60]
            f.write(ip+','+'['+' '.join(map(str, sequence))+']'+'\n')
    # print(statistics.mean(elps))
    f.close()


def generate_outliers02():
    # for d in ['v(0-100)', 'v(100-500)', 'v(500-1200)', 'v(1200+)']:
    filecontents = None
    f = open(
        '../ipid_prediction/Dataset/validation_data/icmp_global.outliers.data', 'w')
    with open('../ipid_prediction/Dataset/validation_data/icmp_global.miss.data', 'r') as filehandle:
        filecontents = filehandle.readlines()
    #indices = random.sample(range(0, len(filecontents)), int(len(filecontents)*0.1))
    # print(indices)
    for i, line in enumerate(filecontents):
        fields = line.split(",")
        if len(fields) < 3:
            continue
        #ns = fields[1]
        ip = fields[0]
        dataStr = fields[1]
        sequence = extract(dataStr)[0:60]
        MAX = 65536
        # if i in indices:
        rands = random.sample(range(0, MAX), 3)  # 5% outliers
        locs = list()
        for i, v in enumerate(sequence):
            if v == -1:
                locs.append(i)
        for i, v in enumerate(locs):
            sequence[v] = rands[i]
        f.write(ip+','+'['+' '.join(map(str, sequence))+']'+'\n')
    f.close()


def generate_outliers():
    # for d in ['v(0-100)', 'v(100-500)', 'v(500-1200)', 'v(1200+)']:
    for d in ['v(1200+)']:
        filecontents = None
        f = open('../ipid_prediction/Dataset/validation_data/icmp_global.' +
                 d+'.outliers.data', 'w')
        with open('../ipid_prediction/Dataset/validation_data/icmp_global.'+d+'.data', 'r') as filehandle:
            filecontents = filehandle.readlines()
        #indices = random.sample(range(0, len(filecontents)), int(len(filecontents)*0.1))
        # print(indices)
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 3:
                continue
            #ns = fields[1]
            ip = fields[0]
            dataStr = fields[1]
            sequence = extract(dataStr)[0:60]
            MAX = 65536
            # if i in indices:
            rands = random.sample(range(0, MAX), 1)  # 10% outliers
            print(rands)
            locs = random.sample(range(30, len(sequence)), 1)
            for i, v in enumerate(locs):
                sequence[v] = rands[i]
            f.write(ip+','+'['+' '.join(map(str, sequence))+']'+'\n')
        f.close()


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
    # for d in ['v(0-100)', 'v(100-500)', 'v(500-1200)', 'v(1200+)']:
    filecontents = None
    f = open(
        '../ipid_prediction/Dataset/validation_data/icmp_global.changes.data', 'w')
    with open('../ipid_prediction/Dataset/validation_data/icmp_global.data', 'r') as filehandle:
        filecontents = filehandle.readlines()
    #indices = random.sample(range(0, len(filecontents)), int(len(filecontents)*0.1))
    # print(indices)
    for i, line in enumerate(filecontents):
        fields = line.split(",")
        if len(fields) < 3:
            continue
        ip = fields[0]
        idStr = fields[1]
        timeStr = fields[2]
        ids = extract(idStr)
        times = extract(timeStr)
        MAX = 65536
        new_ids, new_times = hole_loss(ids, times, 0.10)
        f.write(ip+','+'['+' '.join(map(str, new_ids))+']' +
                ',['+' '.join(map(str, new_times))+']'+'\n')
    f.close()


def generate_random_loss_data():
    # for d in ['v(0-100)', 'v(100-500)', 'v(500-1200)', 'v(1200+)']:
    filecontents = None
    f = open('../ipid_prediction/Dataset/validation_data/icmp_global.miss.data', 'w')
    with open('../ipid_prediction/Dataset/validation_data/icmp_global.data', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 3:
                continue
            #ns = fields[1]
            ip = fields[0]
            idStr = fields[1]
            timeStr = fields[2]
            ids = extract(idStr)
            times = extract(timeStr)
            ids, times = random_loss(ids, times, loss_rate=0.05)
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
        if len(fields) < 3:
            continue
        ip = fields[0]
        dataStr = fields[1]
        sequence = extract(dataStr)
        sequence = sequence[0:60]
        if i in indices:
            f.write(ip+','+'['+' '.join(map(str, sequence))+']'+'\n')
    f.close()


def eliminate_trans_error(chps_ind, actual, predictions):
    diff = list()
    for i in range(len(actual)):
        # if the turning point is predicted with a prior second, then the main prediction error is on the upper turining point, otherwise, th error is on the lower turning point.
        if i in chps_ind and abs(predictions[i]-actual[i]) > 30000:
            if predictions[i] < actual[i]:
                diff.append(predictions[i]-actual[i] + 65536)
            else:
                diff.append(predictions[i]-actual[i] - 65536)
            continue
        diff.append(predictions[i]-actual[i])
    return diff


def containNAN(data):
    for i in range(len(data)):
        if math.isnan(data[i]):
            return True
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


networks = list()


def count_BGP_Subnetworks():
    with open('../ipid_prediction/Dataset/validation_data/icmp_global.data', 'r') as filehandle:
        filecontents = filehandle.readlines()
        print(len(filecontents))
        for line in filecontents:
            fields = line.split(",")
            if len(fields) < 3:
                continue
            ip = fields[0]
            frags = ip.split('.')
            network = frags[0] + '.' + frags[1] + '.' + frags[2]
            if network in networks:
                continue
            networks.append(network)
    print(len(networks))


def plot_outliers_changes():
    sns.set(rc={'figure.figsize': (6, 3)})
    a = list()
    b = list()
    with open('../training_data/test.data', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for i, line in enumerate(filecontents):
            fields = line.split(",")
            if len(fields) < 2:
                continue
            ip = fields[0]
            print(ip)
            dataStr = fields[1]
            sequence = extract(dataStr)
            if i == 0:
                a = np.array(sequence[46:60])
            if i == 1:
                b = np.array(sequence[18:32])
            if i == 1:
                break
    print(len(a), len(b))
    df = pd.DataFrame({'a': a, 'b': b})
    g = sns.lineplot(data=df)
    g.set_xticks(range(len(df)))
    #g.set_xlabel('Received time (i-th second)', fontsize=10)
    #g.set_ylabel('IP ID values', fontsize=10)
    plt.savefig('../images/outliers_changes.pdf')
    # plt.show()


def grnn():
    
    for l in [5]:
        #f = open('./predictive_analysis/grnn_no_changes_predictive_analysis.res', 'w') #w('+str(l)+')
        # with open('../ipid_prediction/Dataset/validation_data/icmp_global.changes.data', 'r') as filehandle:
        with open('./Datasets/test.data', 'r') as filehandle:
            filecontents = filehandle.readlines()
            for line in filecontents:
                fields = line.split(",")
                if len(fields) < 2:
                    continue
                #ns = fields[1]
                ip = fields[0]
                dataStr = fields[1]
                sequence = extract(dataStr)

                for i, v in enumerate(sequence):
                    if v == -1:
                        sequence[i] = math.nan
                # preprocessing dataset
                #n_steps = 3
                vel = 0
                n_step = 2
                sigma = 0.1
                #history, actual = sequence[30-l:30], sequence[30:60]
                history, actual = sequence[0:5], sequence[5:]
                #n_hold_out = int(len(history)*2/10)
                n_hold_out = None
                elps = list()
                chps_ind = list()
                predictions = list()
                outlier_ind = list()
                #tem_actual = sequence[30-l:30]
                tem_actual = sequence[0:5]
                
                new_window = list()
                # Attention: need to modify the actual data because of the outliers (Done!)
                for i in range(len(actual)+1):
                    start = time.monotonic()
                    MAX = 65536

                    if containNAN(history):
                        vel = computeIpidVelocitySeg(
                            history, list(range(len(history))), MAX)
                    else:
                        # eliminate the outliers' impact
                        vel = computeIpidVelocity02(
                            history, list(range(len(history))), MAX)

                    if vel < 1000:
                        thr = 15000  # experimentially specify the threshold
                    else:
                        thr = 30000

                    if i > 1 and alarm_turning_point(thr, tem_actual[-2], tem_actual[-1], MAX):
                        chps_ind.append(i-2)
                        chps_ind.append(i-1)
                    if i == len(actual):
                        break

                    # history = fill_miss_values(history) # base.res, try linear_interpolate_miss_values
                    history = fill_predicted_values(history, predictions)
                    #new_window = linear_interpolate_miss_values(new_window)
                    '''
						outliers = False
						change = False
						history, change = filter_outliersv2(outliers, history, thr, MAX, tem_actual, outlier_ind)
						##in this method, a slight change will be recognised as an outlier, therefore this method is suitable to quite stable IP ID increments.
						#if i > 5:
						#	history, change = filter_outliers_normal_distr(outliers, history, chps_ind, tem_actual, predictions, outlier_ind)
							
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
					        '''

                    one_time_forecast(history, predictions,
                                      n_step, n_hold_out, sigma, MAX)
                    if predictions[-1] < 0:
                        predictions[-1] = 0

                    end = time.monotonic()
                    elps.append(end-start)
                    tem_actual.append(actual[i])
                    history.append(actual[i])
                    history.pop(0)
                # identify change points and then eliminate the error from the transformation at the restore.

                # for i in chps_ind:
                #	print('change points: ', actual[i])
                after_predictions = list()
                for v in predictions:
                    if math.isnan(v):
                        after_predictions.append(v)
                    else:
                        after_predictions.append(round(v))
                predictions = after_predictions

                '''err = list()
					for i in range(len(predictions)):
						if math.isnan(actual[i]): continue
						err.append(abs(predictions[i]-actual[i]))
					#err = np.array(err)
					err = ' '.join(map(str, err))'''
                #rmse = np.mean(array(err)**2)**.5
                #print('Test RMSE: %.3f' % rmse)

                diff = eliminate_trans_error(chps_ind, actual, predictions)
                after_diff = list()
                for v in diff:
                    if math.isnan(v):
                        continue
                    after_diff.append(v)

                err = ' '.join(map(str, after_diff))

                # print(np.abs(after_diff))
                smape = sMAPE02(chps_ind, actual, predictions)
                print('Test sMAPE: %.3f' % smape)
                print('GRNN', predictions)
                

                t = statistics.mean(elps)

                '''pyplot.plot(sequence[0:30]+actual, '-o', label='Expected')
					pyplot.plot(sequence[0:30]+predictions, '-o', label='Predicted')
					pyplot.legend()
					pyplot.show()'''

                '''sns.lineplot(np.array(range(0,60)), sequence[0:30]+predictions, marker="o", label='Predicted')
					sns.lineplot(np.array(range(0,60)), sequence[0:30]+actual, marker="o", label='Expected')
					pyplot.legend()
					pyplot.xlabel('Received time (i-th second)')
					pyplot.ylabel('IP ID value')
					pyplot.savefig('../images/grnn.bad.example.pdf')
					#pyplot.show()
					'''

                '''pyplot.plot(list(range(0,60)), filter_data+history,'-o', label='Filtered', color = 'tab:green')
					pyplot.plot(list(range(0,60)), sequence,'-', label='Expected', color = 'black')
					#pyplot.plot(list(range(0,60)), sequence[0:30]+actual,'-o', label='Expected', color = 'black')
					pyplot.plot(list(range(30,60)), predictions,'-', label='Predicted', color = 'tab:red')
					pyplot.legend()
					pyplot.xticks(fontweight = 'bold')
					pyplot.yticks(fontweight = 'bold')
					pyplot.xlabel('Received time (i-th second)', fontweight = 'bold')
					pyplot.ylabel('IP ID value', fontweight = 'bold')
					pyplot.show()'''
                #f.write(ip+',['+ err +'],'+str(smape)+','+str(t)+'\n')
                
        #f.close()


def interpolate_miss_values(sliding_window):
    s = pd.Series(sliding_window)
    # 'spline'
    return (s.interpolate(method='polynomial', order=2, limit_direction='both').values % 65536).tolist()
    # return (s.interpolate(method='linear', limit_direction='both').values % 65536).tolist()


def linear_interpolate_miss_values(sliding_window):
    s = pd.Series(sliding_window)
    return (s.interpolate(method='linear', limit_direction='both').values % 65536).tolist()
    # return (s.interpolate(method='spline', order = 2, limit_direction='both').values % 65536).tolist()
    # return (s.interpolate(method='pad', limit=2).values % 65536).tolist()


def fill_miss_values(data):
    #if math.isnan(data[0]): data[0] = data[1]
    s = pd.Series(data)
    s = s.interpolate(method='pad')
    return (s.interpolate(method='linear', limit_direction='both').values % 65536).tolist()


def fill_predicted_values(data, predictions):
    if len(predictions) == 0:
        data = fill_miss_values(data)
        return data
    elif math.isnan(data[-1]):
        data[-1] = int(predictions[-1])
    return data


def grnn_interpolate_packet_loss():
    f = open('../training_data/global.grnn.linear.res', 'w')
    with open('../training_data/global.random.loss.0.1.data', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            fields = line.split(",")
            if len(fields) < 3:
                continue
            ip = fields[0]
            dataStr = fields[1]
            sequence = extract(dataStr)
            for i, v in enumerate(sequence):
                if v == -1:
                    sequence[i] = math.nan
            # preprocessing dataset
            n_steps = 3
            n_hold_out = 9
            sliding_window, forecast_samples = sequence[0:30], sequence[30:]
            predictions = list()
            for i in range(len(forecast_samples)):
                #print('sliding_window: ', sliding_window)
                #new_window = interpolate_miss_values(sliding_window)
                new_window = linear_interpolate_miss_values(
                    sliding_window)  # new_window
                #print('new_window: ', new_window)
                one_time_forecast(new_window, predictions,
                                  n_steps, n_hold_out)  # new_window
                new_value = forecast_samples[i]
                sliding_window.append(new_value)
                sliding_window.pop(0)
            # print(predictions)
            predictions = [round(i) for i in predictions]
            #print('predictions: ', predictions)
            #print('forecast_samples: ', forecast_samples)
            diff = np.array(predictions) - np.array(forecast_samples)
            after_diff = list()
            for v in diff:
                if math.isnan(v):
                    continue
                after_diff.append(v)
            # print(-diff) # residual forecast error
            #mae = np.mean(abs(array(after_diff)))
            #print('Test MAE: %.3f' % mae)
            rmse = np.mean(array(after_diff)**2)**.5
            #print('Test RMSE: %.3f' % rmse)
            #mape = np.mean(np.abs(diff)/np.array(actual))
            #print('Test MAPE: %.3f' % mape)
            smape = sMAPE(forecast_samples, predictions)
            #print('Test sMAPE: %.3f' % smape)
            f.write(ip+','+str(rmse) + ','+str(smape)+'\n')
    f.close()


dataset = {
    'ip': [],
    'rmse': [],
    'smape': []
}


def main():

    grnn()


def main02():
    ips_list = list()
    ips = list()
    # with open('../training_data/AlexaWebsites.top50.ns.ips', 'r') as filehandle:
    with open('../evaluate/results/udp_53.alexa.ips.res', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            fields = line.split(",")
            if len(fields) < 1:
                continue
            ip = fields[0]
            ips.append(ip)
            if len(ips) == 10:  # 10
                ips_list.append(ips)
                ips = list()
            if len(ips_list) == 6 and len(ips) == 2:
                ips_list.append(ips)
    # print(ips_list)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for ips in ips_list:
            futures.append(executor.submit(group_ips_measure, ips))
        for future in concurrent.futures.as_completed(futures):
            future.result()

    df = pd.DataFrame(dataset)
    df.to_csv('../training_data/global.grnn.linear.online.res', index=False)


def animate(i):
    data = pd.read_csv('./ipid_data.csv')
    y1 = data['actual']
    y2 = data['prediction']
    x = list(range(len(y1)))
    if x == 31:
        plt.axvline(x=x[-2])
        plt.axvline(x=x[-31])
    plt.cla()
    plt.plot(x, y1, label='Expected')
    plt.plot(x, y2, label='Predicted')

    plt.legend(loc='upper left')
    plt.tight_layout()


if __name__ == "__main__":
    # execute only if run as a script
    main()
