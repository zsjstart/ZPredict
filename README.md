# ZPredict
We develop a tool called ZPredict, which leverages machine learning methodologies for two key tasks: IPID assignment identification, which distinguishes between different IPID assignment mechanisms, and IPID value prediction, which enables the learning of the historical changing behavior of an IPID counter to predict its future IPID values.
ZPredict can be applied for various network measurements, including idle port scanning, IP-level censorship measurement, and inbound SAV measurement.

## IPID Assignment Identification
We improve the previous decision tree (DT)-based classifier developed by Salutari et al. [1].
We enhance Salutari's feature set by incorporating time information and extracting nine additional features from the time and frequency domains of an IPID time series, and implement a new classifier with Support Vector Machine (SVM) model using six existing features and nine new features, as listed in the following experimental results.

### Experiment results of two classifiers in terms of the performance: macro-averaging precision, recall, F1-score, and accuracy on the holdout data.

|     Classifiers     | DT         | SVM        |
|--------------------|-----------------|----------------|
| Precision       |    93.1%   | 99.7%           |
| Recall      | 92.9%      | 99.7%           |
| F1-score      | 92.9%         | 99.7%           |
| HoldOut Acc      | 92.2%         | 98.6%           |



## IPID Value Prediction

