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
#import features_extraction_lib
from features_extraction_lib import extract
import re
import warnings
warnings.filterwarnings("ignore")


class go_string(Structure):
    _fields_ = [
        ("p", c_char_p),
        ("n", c_int)]


def modify(times):
    start = times[0]
    i = 0
    for time in times:
        times[i] = int(round(float(time - start)/1000000.0))
        i += 1
    return times


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
    # print(agg)
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
        if (actual[i] + predictions[i]) != 0:
            if (actual[i] + predictions[i]) < 0:
                continue
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


def MAPE(chps_ind, actual, predictions):
    res = list()
    for i in range(len(actual)):
        if i in chps_ind and abs(predictions[i]-actual[i]) > 30000:
            if predictions[i] < actual[i]:
                pre = predictions[i] + 65536
                res.append(abs(pre-actual[i]) / actual[i])
            else:
                ac = actual[i] + 65536
                res.append(abs(predictions[i]-ac) / ac)
            continue
        if (actual[i] + predictions[i]) != 0:
            if (actual[i] + predictions[i]) < 0:
                continue
            res.append(abs(predictions[i]-actual[i]) / actual[i])
        else:
            res.append(0)
    after_res = list()
    for v in res:
        if math.isnan(v):
            continue
        after_res.append(v)
    return np.mean(after_res)


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


def alarm_turning_point(thr, a1, a2, MAX):
    alarm = False
    delta = a2 - a1
    # a2-a1+MAX approximates to a2 (close to 1 in ideal)
    if delta < 0 and rela_diff(a1, a2, MAX) < thr:
        alarm = True
    return alarm


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


def lr():

    for l in [5]:
        #f = open('./predictive_analysis/lr_changes_predictive_analysis.res', 'w') #w('+str(l)+')
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

                vel = 0
                
                
                #history, actual = sequence[30-l:30], sequence[30:]
                history, actual = sequence[0:5], sequence[5:]
                times = list()
                for i in range(len(history)):
                    times.append(i)
                tHistory = times
                #n_hold_out = int(len(history)*3/10)
                n_hold_out = None
                elps = list()
                chps_ind = list()
                predictions = list()
                outlier_ind = list()
                #tem_actual = sequence[30-l:30]
                tem_actual = sequence[0:5]
                # for plot: filtered data
                #filter_data = filter_outliers02(True, history, 65536)
                #filter_data = fill_miss_values(filter_data)
                # for plot
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

                    # identify the truning point and make a preprocessing
                    wraps, new_window = data_preprocess(thr, history, MAX)
                    k = len(wraps)
                    ntime = tHistory[-1]+1
                    one_time_forecast(new_window, tHistory,
                                      ntime, k, predictions, MAX)

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
                print('LR', predictions)
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


def fill_miss_values(data):
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


def split_global_data():
    ofile = open('./Datasets/benchmark.data', 'w')
    with open('./Datasets/merge_global.data', 'r') as filehandle:
        filecontents = filehandle.readlines()
        for line in filecontents:
            fields = line.split(",")
            if len(fields) < 2: continue
            ip = fields[0]
            dataStr = fields[1]
            sequence = extract(dataStr)
            series1 = sequence[0:35]
            series2 = sequence[35:70]
            series3 = sequence[65:100]
            print(series1)
            ofile.write(ip+',['+' '.join(map(str, series1))+']\n')
            ofile.write(ip+',['+' '.join(map(str, series2))+']\n')
            ofile.write(ip+',['+' '.join(map(str, series3))+']\n')
    ofile.close()


def main():
    lr()
    #split_global_data()


if __name__ == "__main__":
    # execute only if run as a script
    main()
