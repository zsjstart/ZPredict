from sklearn import svm
from sklearn.neighbors import KNeighborsClassifier
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn import metrics
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn import preprocessing
from sklearn.model_selection import StratifiedKFold
import math
import numpy as np
import pickle
from sklearn.metrics import plot_confusion_matrix
import matplotlib.pyplot as plt
import joblib
import time 
from svm import test_case02
from sklearn.inspection import permutation_importance


def feature_importance(X,y, k):
	#X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3,random_state=0, stratify=y)
	scaler = joblib.load('./knn_scaler.gz')
	#X_train = scaler.transform(X_train)
	#X_test = scaler.transform(X_test)
	X = scaler.transform(X)
	clf = KNeighborsClassifier(n_neighbors=k) 
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

def cross_validation(X,y,k):
	accuracy = []
	precision = []
	recall = []
	f1_score = []
	kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=0)
	
	elps = []
	scaler = joblib.load('./knn_scaler.gz')
	# enumerate the splits and summarize the distributions
	for train_ix, test_ix in kfold.split(X, y):
		X_train, X_test = X[train_ix], X[test_ix]
		X_train = scaler.transform(X_train)
		X_test = scaler.transform(X_test)
		y_train, y_test = y[train_ix], y[test_ix]
		#clf = svm.SVC(kernel='linear') # Linear Kernel
		clf = KNeighborsClassifier(n_neighbors=k) # n_neighbors = 20#, 5
		#start = time.monotonic()
		clf.fit(X_train, y_train)
		#end = time.monotonic()
		#elps.append(end-start)
		start = time.monotonic()
		y_pred = clf.predict(X_test)
		end = time.monotonic()
		elps.append(end-start)
		
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

def grid_search(f, X, y, k):
	accuracy = []
	precision = []
	recall = []
	f1_score = []
	kfold = StratifiedKFold(n_splits=10, shuffle=True, random_state=0)
	
	scaler = joblib.load('./knn_scaler.gz')
	# enumerate the splits and summarize the distributions
	for train_ix, test_ix in kfold.split(X, y):
		X_train, X_test = X[train_ix], X[test_ix]
		X_train = scaler.transform(X_train)
		X_test = scaler.transform(X_test)
		y_train, y_test = y[train_ix], y[test_ix]
		#clf = svm.SVC(kernel='linear') # Linear Kernel
		clf = KNeighborsClassifier(n_neighbors=k) # n_neighbors = 20#, 5
		clf.fit(X_train, y_train)
		y_pred = clf.predict(X_test)
		
		accuracy.append(metrics.accuracy_score(y_test, y_pred))
		precision.append(metrics.precision_score(y_test, y_pred, average='macro'))
		recall.append(metrics.recall_score(y_test, y_pred, average='macro'))
		f1_score.append(metrics.f1_score(y_test, y_pred, average='macro'))
	
	f.write("k is {}, Accuracy is {}, Precision is {}, Recall is {}, F1_score is {} \n".format(k, np.mean(accuracy), np.mean(precision), np.mean(recall), np.mean(f1_score)))
		
def plot_cm(clf, X_test, y_test):
	classes = ['G', 'P', 'R', 'C', 'A']
	font = {
    		'weight' : 'bold',
    		'size'   : 14}
	plt.rc('font', **font)
	plot_confusion_matrix(clf, X_test, y_test, display_labels=classes, cmap=plt.cm.Blues, normalize='true') #cmap=plt.cm.Blues
	plt.ylabel('True class',fontweight='bold')
	plt.xlabel('Predicted class', fontweight='bold')
	plt.subplots_adjust(left=0.2)
	#plt.show()
	plt.savefig('../images/cm_knn_m(0.2).pdf')

def knn_classifier(X, y, k):

	scaler = joblib.load('./knn_scaler.gz')
	X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3,random_state=0, stratify=y)
	X_train = scaler.transform(X_train)
	X_test = scaler.transform(X_test)
	clf = KNeighborsClassifier(n_neighbors=k)
	clf.fit(X_train, y_train)
	y_pred = clf.predict(X_test)	
	
	with open('knn_classifier.pkl', 'wb') as f:
    		pickle.dump(clf, f)
	#print(metrics.confusion_matrix(y_test, y_pred, labels=[1,2,3,4,5]))
	#plot_cm(clf, X_test, y_test)
	print("Accuracy:",metrics.accuracy_score(y_test, y_pred))

def prediction(X, scaler):
	X = scaler.transform(X)
	clf = None
	with open('./knn_classifier.pkl', 'rb') as f:
    		clf = pickle.load(f)
	y_pred = clf.predict(X)
	return np.array(y_pred)

def test(X_test, y_test, scaler, plot):

	#scaler= MinMaxScaler(feature_range=(-1,1))
	
	X_test = scaler.transform(X_test)
	
	clf = None
	with open('./knn_classifier.pkl', 'rb') as f:
    		clf = pickle.load(f)
	
	y_pred = clf.predict(X_test)
	if plot:
		plot_cm(clf, X_test, y_test)
	f = open('../training_data/new_data/mis_class_knn_m(0.2).res', 'w')
	a = np.array(y_pred)
	for i in range(len(a)):
		if y_test[i] == 5 and a[i] == 3:
			f.write(str(i)+','+str(a[i])+'\n')
	acc = metrics.accuracy_score(y_test, y_pred)
	return acc

def test_case01():
	accs = []
	for r in [0.20]:
		data = pd.read_csv('./ipid_new_data_m('+str(r)+')_frag_9f.csv')
		#data = pd.read_csv('./ipid_new_data_m(0.05)_pad_6f.csv')
	#for l in [5, 15, 25, 35, 45, 55, 65, 75, 85, 95]:
		#data = pd.read_csv('../training_data/new_data/ipid_new_data_'+str(l)+'_5c_9f.csv')
		X_test = data.iloc[:,1:10].values
		y_test = data.iloc[:,10].values
		scaler = joblib.load('./knn_scaler.gz')
		acc = test(X_test, y_test, scaler, True)
		accs.append(acc)
	print(accs)

def save_scaler(X):
	scaler = MinMaxScaler(feature_range=[-1,1]).fit(X)
	joblib.dump(scaler, './knn_scaler.gz')

def main():
	
	data = pd.read_csv('./ipid_new_data_all_9f.csv')
	
	ips = data.iloc[:,0].values
	X = data.iloc[:,1:10].values
	y = data.iloc[:,10].values
	
	save_scaler(X)
	'''f = open('./Grid_Search/knn_grid_search.9f.res', 'w')
	for k in range(1, 20, 2):
		grid_search(f, X,y, k)'''
	#cross_validation(X,y, k=3)
	knn_classifier(X,y, k=3)
	test_case01()
	#feature_importance(X,y, k=3)

if __name__ == "__main__":
    # execute only if run as a script
    main()
