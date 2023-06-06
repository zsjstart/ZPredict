from sklearn import svm
from sklearn.inspection import permutation_importance
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn import metrics
from sklearn.metrics import r2_score
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn import preprocessing
from sklearn.model_selection import StratifiedKFold, KFold
import math
import numpy as np
import pickle
from sklearn.metrics import plot_confusion_matrix, classification_report
import matplotlib.pyplot as plt
import joblib
import time
from collections import Counter
from numpy import where
from matplotlib import pyplot
from sklearn.linear_model import LinearRegression
from imblearn.over_sampling import SMOTE
import scikitplot as skplt
from sklearn.preprocessing import label_binarize
from sklearn.multiclass import OneVsRestClassifier
from itertools import cycle
import matplotlib as mpl
from neupy import algorithms

def feature_importance(X,y):
	X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3,random_state=0, stratify=y)
	scaler = joblib.load('./svm_scaler.gz')
	X_train = scaler.transform(X_train)
	X_test = scaler.transform(X_test)
	X = scaler.transform(X)
	
	clf = svm.SVC(kernel='rbf', C = 1000, random_state=0)
	#clf.fit(X_train, y_train)
	clf.fit(X, y)
	#plot_cm(clf, X_test, y_test)
	perm_importance = permutation_importance(clf, X, y, n_repeats=10, random_state=100)

	#feature_names = ['\u0394max(s)', '\u0394max(x)', '\u0394max(y)','Autocorr', 'Crosscorr', 'B','F_centroid','F_rolloff']
	feature_names = ['v', '\u0394max(s)', '\u0394max(x)', '\u0394max(y)','Autocorr', 'Crosscorr', 'B','F_d', 'F_rolloff']
	features = np.array(feature_names)

	sorted_idx = perm_importance.importances_mean.argsort()
	plt.rcParams["figure.figsize"] = (7,5)
	font = {
    		'weight' : 'bold',
    		'size'   : 14}
	plt.rc('font', **font)
	plt.barh(features[sorted_idx], perm_importance.importances_mean[sorted_idx], color='olive')
	plt.xlabel("Feature Importance", fontweight= 'bold')
	plt.subplots_adjust(left=0.2, top= 0.90)
	plt.show()
	


def cross_validation(X,y, c):
	accuracy = []
	precision = []
	recall = []
	f1_score = []
	#kfold = KFold(n_splits=10, shuffle=True, random_state=0)
	kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=0)
	elps = []
	#scaler = MinMaxScaler(feature_range=[-1,1]).fit(X)
	#joblib.dump(scaler, './svm_scaler.gz')
	scaler = joblib.load('./svm_scaler.gz')
	# enumerate the splits and summarize the distributions
	for train_ix, test_ix in kfold.split(X, y):
		X_train, X_test = X[train_ix], X[test_ix]
		#scaler = StandardScaler().fit(X_train)
		X_train = scaler.transform(X_train)
		X_test = scaler.transform(X_test)
		y_train, y_test = y[train_ix], y[test_ix]
		#clf = svm.SVC(kernel='rbf', C = 4) # Linear Kernel
		clf = svm.SVC(kernel='rbf', C = c, random_state=0) #(1, 10, 100, 1000)
		#start = time.monotonic()
		clf.fit(X_train, y_train)
		#end = time.monotonic()
		#elps.append(end-start)
		start = time.monotonic()
		y_pred = clf.predict(X_test)
		end = time.monotonic()
		elps.append(end-start)
		#plot_cm(clf, X_test, y_test)
		accuracy.append(metrics.accuracy_score(y_test, y_pred))
		precision.append(metrics.precision_score(y_test, y_pred, average='macro'))
		recall.append(metrics.recall_score(y_test, y_pred, average='macro'))
		f1_score.append(metrics.f1_score(y_test, y_pred, average='macro'))
		#cm = metrics.confusion_matrix(y_test, y_pred, labels=[1,2,3,4,5])
		
	print("Time cost:", np.mean(elps))
	print("Accuracy:",np.mean(accuracy))
	print("Precision:",np.mean(precision))
	print("Recall:",np.mean(recall))
	print("F1_score:",np.mean(f1_score))

def grid_search(f, X, y, c):
	accuracy = []
	precision = []
	recall = []
	f1_score = []
	#kfold = KFold(n_splits=10, shuffle=True, random_state=0)
	kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=0)
	#scaler = MinMaxScaler(feature_range=[-1,1]).fit(X)
	#joblib.dump(scaler, './svm_scaler.gz')
	scaler = joblib.load('./svm_scaler.gz')
	# enumerate the splits and summarize the distributions
	for train_ix, test_ix in kfold.split(X, y):
		X_train, X_test = X[train_ix], X[test_ix]
		#scaler = StandardScaler().fit(X_train)
		X_train = scaler.transform(X_train)
		X_test = scaler.transform(X_test)
		y_train, y_test = y[train_ix], y[test_ix]
		#clf = svm.SVC(kernel='rbf', C = 4) # Linear Kernel
		clf = svm.SVC(kernel='rbf', C = c, random_state=0) #(1, 10, 100, 1000)
		clf.fit(X_train, y_train)
		y_pred = clf.predict(X_test)
		
		accuracy.append(metrics.accuracy_score(y_test, y_pred))
		precision.append(metrics.precision_score(y_test, y_pred, average='macro'))
		recall.append(metrics.recall_score(y_test, y_pred, average='macro'))
		f1_score.append(metrics.f1_score(y_test, y_pred, average='macro'))
	
	f.write("c is {}, Accuracy is {}, Precision is {}, Recall is {}, F1_score is {} \n".format(c, np.mean(accuracy), np.mean(precision), np.mean(recall), np.mean(f1_score)))

		
def plot_cm(clf, X_test, y_test):
	classes = ['G', 'P', 'R', 'C', 'A']
	font = {
    		'weight' : 'bold',
    		'size'   : 14}
	plt.rc('font', **font)
	plot_confusion_matrix(clf, X_test, y_test, display_labels=classes, cmap=plt.cm.Blues, normalize='true')
	plt.ylabel('True class',fontweight='bold')
	plt.xlabel('Predicted class', fontweight='bold')
	plt.subplots_adjust(left=0.2)
	plt.show()

def save_scaler(X):
	scaler = MinMaxScaler(feature_range=[-1,1]).fit(X)
	joblib.dump(scaler, './svm_scaler.gz')

def svm_classifier(X, y, c):
	X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3,random_state=0, stratify=y) # 70% training and 30% test, stratify=y
	#joblib.dump(scaler, './svm_scaler.gz')
	scaler = joblib.load('./svm_scaler.gz')
	X_train = scaler.transform(X_train)
	X_test = scaler.transform(X_test)
	
	clf = svm.SVC(kernel='rbf', C = c, random_state=0) # Linear Kernel
	#clf = svm.LinearSVC()
	clf.fit(X_train, y_train)
	y_pred = clf.predict(X_test)
	
	with open('svm_classifier.pkl', 'wb') as f:
    		pickle.dump(clf, f)
	#print(metrics.confusion_matrix(y_test, y_pred, labels=[1,2,3,4,5]))
	#plot_cm(clf, X_test, y_test)
	print(classification_report(y_test, y_pred))
	print("Accuracy:",metrics.accuracy_score(y_test, y_pred))
	
def test(X_test, y_test, scaler, plot):

	#scaler= MinMaxScaler(feature_range=(-1,1))
	
	X_test = scaler.transform(X_test)
	
	clf = None
	with open('./svm_classifier.pkl', 'rb') as f:
    		clf = pickle.load(f)
	
	y_pred = clf.predict(X_test)
	if plot:
		plot_cm(clf, X_test, y_test)
	a = np.array(y_pred)
	acc = metrics.accuracy_score(y_test, y_pred)
	#print('acc: ', acc)
	return acc

def prediction(X, scaler):
	X = scaler.transform(X)
	clf = None
	with open('./svm_classifier.pkl', 'rb') as f:
    		clf = pickle.load(f)
	y_pred = clf.predict(X)
	return np.array(y_pred)


switcher = {
	2: 'per-host',
	3: 'random',
	4: 'constant',
	5: 'anomalous',
	1: 'global',
	9: 'test',
}

def test_case():
	data = pd.read_csv('../training_data/new_data/ipid_new_data_high_vel_6f.csv')
	X_test = data.iloc[:,1:7].values
	y_test = data.iloc[:,7].values
	scaler = joblib.load('./svm_scaler.gz')
	test(X_test, y_test, scaler, False)
	

def main():
	
	data = pd.read_csv('./ipid_new_data_all_9f.csv')
	
	ips = data.iloc[:,0].values
	X = data.iloc[:,1:10].values
	y = data.iloc[:,10].values
	
	save_scaler(X)
	'''f = open('./Grid_Search/svm_grid_search.9f.res', 'w')
	c_degrees = [1, 10, 50, 100, 200, 400, 600, 800, 1000, 10000]
	for c in c_degrees:
		grid_search(f, X,y, c)'''
		
	#feature_importance(X,y)
	#cross_validation(X,y, c = 1000)
	svm_classifier(X, y, c=1000)
	
	
		

if __name__ == "__main__":
    # execute only if run as a script
    main()
