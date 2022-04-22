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
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
import time
from sklearn.model_selection import train_test_split
import pickle
import matplotlib.pyplot as plt
from sklearn.metrics import plot_confusion_matrix, classification_report
import matplotlib as mpl
from sklearn.inspection import permutation_importance

def feature_importance(X,y, d):
	X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3,random_state=0, stratify=y)
	scaler = joblib.load('./rfc_scaler.gz')
	X_train = scaler.transform(X_train)
	X_test = scaler.transform(X_test)
	X = scaler.transform(X)
	clf = RandomForestClassifier(max_depth=d, random_state=0) 
	clf.fit(X_train, y_train)
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

def cross_validation(X,y,d):
	accuracy = []
	precision = []
	recall = []
	f1_score = []
	kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=0)
	scaler = joblib.load('./rfc_scaler.gz')
	elps = []
	# enumerate the splits and summarize the distributions
	for train_ix, test_ix in kfold.split(X, y):
		X_train, X_test = X[train_ix], X[test_ix]
		y_train, y_test = y[train_ix], y[test_ix]
		X_train = scaler.transform(X_train)
		X_test = scaler.transform(X_test)
		rfc = RandomForestClassifier(max_depth=d, random_state=0)
		#start = time.monotonic()
		rfc.fit(X_train,y_train)
		#end = time.monotonic()
		#elps.append(end-start)
		start = time.monotonic()
		y_pred = rfc.predict(X_test)
		end = time.monotonic()
		elps.append(end-start)
		accuracy.append(metrics.accuracy_score(y_test, y_pred))
		precision.append(metrics.precision_score(y_test, y_pred, average='macro'))
		recall.append(metrics.recall_score(y_test, y_pred, average='macro'))
		f1_score.append(metrics.f1_score(y_test, y_pred, average='macro'))
	print("Time cost:", np.mean(elps)) 
	print("Accuracy:",np.mean(accuracy))
	print("Precision:",np.mean(precision))
	print("Recall:",np.mean(recall))
	print("F1_score:",np.mean(f1_score))

def grid_search(f, X, y, d):
	accuracy = []
	precision = []
	recall = []
	f1_score = []
	kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=0)
	
	scaler = joblib.load('./rfc_scaler.gz')
	# enumerate the splits and summarize the distributions
	for train_ix, test_ix in kfold.split(X, y):
		X_train, X_test = X[train_ix], X[test_ix]
		X_train = scaler.transform(X_train)
		X_test = scaler.transform(X_test)
		y_train, y_test = y[train_ix], y[test_ix]
		rfc = RandomForestClassifier(max_depth=d, random_state=0)
		rfc.fit(X_train,y_train)
		y_pred = rfc.predict(X_test)
		accuracy.append(metrics.accuracy_score(y_test, y_pred))
		precision.append(metrics.precision_score(y_test, y_pred, average='macro'))
		recall.append(metrics.recall_score(y_test, y_pred, average='macro'))
		f1_score.append(metrics.f1_score(y_test, y_pred, average='macro'))
	
	f.write("d is {}, Accuracy is {}, Precision is {}, Recall is {}, F1_score is {} \n".format(d, np.mean(accuracy), np.mean(precision), np.mean(recall), np.mean(f1_score)))

def save_scaler(X):
	scaler = MinMaxScaler(feature_range=[-1,1]).fit(X)
	#scaler = StandardScaler().fit(X)
	joblib.dump(scaler, './rfc_scaler.gz')

def plot_cm(clf, X_test, y_test):
	classes = ['G', 'P', 'R', 'C', 'A']
	font = {
    		'weight' : 'bold',
    		'size'   : 12}
	plt.rc('font', **font)
	plot_confusion_matrix(clf, X_test, y_test, display_labels=classes, cmap=plt.cm.Blues, normalize='true')
	plt.ylabel('True class',fontweight='bold')
	plt.xlabel('Predicted class', fontweight='bold')
	plt.subplots_adjust(left=0.2)
	#plt.show()
	plt.savefig('../images/cm_rf(six).pdf')

def test(X_test, y_test, scaler, plot):

	#scaler= MinMaxScaler(feature_range=(-1,1))
	
	X_test = scaler.transform(X_test)
	
	clf = None
	with open('./rf_classifier.pkl', 'rb') as f:
    		clf = pickle.load(f)
	
	y_pred = clf.predict(X_test)
	if plot:
		plot_cm(clf, X_test, y_test)
	a = np.array(y_pred)
	items = []
	for i in range(len(a)):
		if a[i] == 5 and y_test[i] ==3:
			items.append(i)
	acc = metrics.accuracy_score(y_test, y_pred)
	return acc

def test_case01():
	accs = []
	#for r in [0.05, 0.10, 0.15, 0.20]:
	#for r in [0.20]:
		#data = pd.read_csv('../training_data/new_data/ipid_new_data_m('+str(r)+')_frag_9f.csv')
	for l in [5, 15, 25, 35, 45, 55, 65, 75, 85, 95]:
		data = pd.read_csv('../training_data/new_data/ipid_new_data_'+str(l)+'_5c_9f.csv')
		X_test = data.iloc[:,1:10].values
		y_test = data.iloc[:,10].values
		scaler = joblib.load('./rfc_scaler.gz')
		acc = test(X_test, y_test, scaler, True)
		accs.append(acc)
	print(accs)


def rf_classifier(X, y, d):
	X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3,random_state=0, stratify=y) # 70% training and 30% test, stratify=y
	scaler = joblib.load('./rfc_scaler.gz')
	X_train = scaler.transform(X_train)
	X_test = scaler.transform(X_test)
	rfc = RandomForestClassifier(max_depth=d, random_state=0)
	rfc.fit(X_train,y_train)
	y_pred = rfc.predict(X_test)
	
	with open('rf_classifier.pkl', 'wb') as f:
    		pickle.dump(rfc, f)
	plot_cm(rfc, X_test, y_test)
	print("Accuracy:",metrics.accuracy_score(y_test, y_pred))


def main():
	
	data = pd.read_csv('../training_data/ipid_new_data_all_9f.csv')
	ips = data.iloc[:,0].values
	X = data.iloc[:,1:10].values
	y = data.iloc[:,10].values
	save_scaler(X)
	
	'''f = open('./Grid_Search/rf_grid_search.9f.res', 'w')
	for d in range(3, 20, 2):
		grid_search(f, X, y, d)'''
	
	#cross_validation(X,y, d=9)
	rf_classifier(X,y, d=9)
	test_case01()
	#feature_importance(X,y, d=9)
			
				
	

if __name__ == "__main__":
    # execute only if run as a script
    main()
