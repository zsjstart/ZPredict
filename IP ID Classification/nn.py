from numpy import mean
from numpy import std
from sklearn.datasets import make_multilabel_classification
from sklearn.model_selection import RepeatedKFold
from keras.models import Sequential
from keras.layers import Dense
from sklearn.metrics import accuracy_score
import pandas as pd
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from neupy import algorithms
from sklearn import metrics
from sklearn.model_selection import StratifiedKFold
import numpy as np
import joblib
import math
import time
from sklearn.model_selection import train_test_split
import pickle
import matplotlib.pyplot as plt
from sklearn.metrics import plot_confusion_matrix, classification_report

def cross_validation(X,y,s):
	accuracy = []
	precision = []
	recall = []
	f1_score = []
	kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=0)
	scaler = joblib.load('./grnn_scaler.gz')
	elps = []
	# enumerate the splits and summarize the distributions
	for train_ix, test_ix in kfold.split(X, y):
		try:
			X_train, X_test = X[train_ix], X[test_ix]
			y_train, y_test = y[train_ix], y[test_ix]
			X_train = scaler.transform(X_train)
			X_test = scaler.transform(X_test)
			grnn = algorithms.GRNN(std=s, verbose=False)
			#start = time.monotonic()
			grnn.train(X_train, y_train)
			#end = time.monotonic()
			#elps.append(end-start)
			start = time.monotonic()
			yhat = grnn.predict(X_test)
			end = time.monotonic()
			elps.append(end-start)
			# round probabilities to class labels
			yhat = yhat.round()
			y_pred = yhat.reshape(-1)
			accuracy.append(metrics.accuracy_score(y_test, y_pred))
			precision.append(metrics.precision_score(y_test, y_pred, average='macro'))
			recall.append(metrics.recall_score(y_test, y_pred, average='macro'))
			f1_score.append(metrics.f1_score(y_test, y_pred, average='macro'))
		except:
			continue
	print("Time cost:", np.mean(elps)) 
	print("Accuracy:",np.mean(accuracy))
	print("Precision:",np.mean(precision))
	print("Recall:",np.mean(recall))
	print("F1_score:",np.mean(f1_score))

def grid_search(f, X, y, s):
	accuracy = []
	precision = []
	recall = []
	f1_score = []
	kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=0)
	
	scaler = joblib.load('./grnn_scaler.gz')
	# enumerate the splits and summarize the distributions
	for train_ix, test_ix in kfold.split(X, y):
		try: 
			X_train, X_test = X[train_ix], X[test_ix]
			X_train = scaler.transform(X_train)
			X_test = scaler.transform(X_test)
			y_train, y_test = y[train_ix], y[test_ix]
			grnn = algorithms.GRNN(std=s, verbose=False)
			grnn.train(X_train, y_train)
			yhat = grnn.predict(X_test)
			# round probabilities to class labels
			yhat = yhat.round()
			y_pred = yhat.reshape(-1)
			accuracy.append(metrics.accuracy_score(y_test, y_pred))
			precision.append(metrics.precision_score(y_test, y_pred, average='macro'))
			recall.append(metrics.recall_score(y_test, y_pred, average='macro'))
			f1_score.append(metrics.f1_score(y_test, y_pred, average='macro'))
		except:
			continue
	
	f.write("s is {}, Accuracy is {}, Precision is {}, Recall is {}, F1_score is {} \n".format(s, np.mean(accuracy), np.mean(precision), np.mean(recall), np.mean(f1_score)))

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
	
def test(X_test, y_test, scaler, plot):

	#scaler= MinMaxScaler(feature_range=(-1,1))
	
	X_test = scaler.transform(X_test)
	
	clf = None
	with open('./grnn_classifier.pkl', 'rb') as f:
    		clf = pickle.load(f)
	
	y_pred = clf.predict(X_test)
	y_pred = y_pred.round().reshape(-1)
	acc = metrics.accuracy_score(y_test, y_pred)
	return acc

def test_case01():
	accs = []
	for r in [0.05, 0.10, 0.15, 0.20]:
		data = pd.read_csv('./ipid_new_data_m('+str(r)+')_frag_9f.csv')
	#for l in [5, 15, 25, 35, 45, 55, 65, 75, 85, 95]:
	#	data = pd.read_csv('../training_data/new_data/ipid_new_data_'+str(l)+'_5c_9f.csv')
		X_test = data.iloc[:,1:10].values
		y_test = data.iloc[:,10].values
		scaler = joblib.load('./grnn_scaler.gz')
		acc = test(X_test, y_test, scaler, True)
		accs.append(acc)
	print(accs)


def grnn_classifier(X, y, s):
	X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3,random_state=0, stratify=y) # 70% training and 30% test, stratify=y
	scaler = joblib.load('./grnn_scaler.gz')
	X_train = scaler.transform(X_train)
	X_test = scaler.transform(X_test)
	grnn = algorithms.GRNN(std=s, verbose=False)
	grnn.train(X_train, y_train)
	yhat = grnn.predict(X_test)
	# round probabilities to class labels
	yhat = yhat.round()
	y_pred = yhat.reshape(-1)
	
	with open('grnn_classifier.pkl', 'wb') as f:
    		pickle.dump(grnn, f)
	#print(metrics.confusion_matrix(y_test, y_pred, labels=[1,2,3,4,5]))
	#plot_cm(clf, X_test, y_test)
	print("Accuracy:",metrics.accuracy_score(y_test, y_pred))
	
def save_scaler(X):
	scaler = MinMaxScaler(feature_range=[-1,1]).fit(X)
	#scaler = StandardScaler().fit(X)
	joblib.dump(scaler, './grnn_scaler.gz')


def main():	
	data = pd.read_csv('../training_data/ipid_new_data_all_9f.csv')
	ips = data.iloc[:,0].values
	X = data.iloc[:,1:10].values
	y = data.iloc[:,10].values
	save_scaler(X)
	
	'''f = open('./Grid_Search/grnn_grid_search.6f.res', 'w')
	s = 0.1
	while s < 1.0:
		grid_search(f, X,y,s)
		s = s + 0.1'''
		
	#cross_validation(X,y,s=0.1)
	grnn_classifier(X,y,s=0.1)
	test_case01()

if __name__ == "__main__":
    # execute only if run as a script
    main()
