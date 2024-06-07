# ZPredict
We develop a tool called ZPredict, which leverages machine learning methodologies for two key tasks: IPID assignment identification, which distinguishes between different IPID assignment mechanisms, and IPID value prediction, which enables the learning of the historical changing behavior of an IPID counter to predict its future IPID values.
ZPredict can be applied for various network measurements, including idle port scanning, IP-level censorship measurement, and inbound SAV measurement.

## IPID Assignment Identification
This mechanism is aimed to capture appropriate IPIDs, e.g., global IPID counters, from the Internet for implementing various measurements.
We improve the previous decision tree (DT)-based classifier developed by Salutari et al. [1].
We enhance Salutari's feature set by incorporating time information and extracting nine additional features from the time and frequency domains of an IPID time series, and implement a new classifier with Support Vector Machine (SVM) model using six existing features and nine new features, as listed in the following experimental results.

### Experiment results of two classifiers in terms of the performance: macro-averaging precision, recall, F1-score, and accuracy on the holdout data.

|     Classifiers     | DT         | SVM        |
|--------------------|-----------------|----------------|
| Precision       |    93.1%   | 99.7%           |
| Recall      | 92.9%      | 99.7%           |
| F1-score      | 92.9%         | 99.7%           |
| HoldOut Acc      | 92.2%         | 98.6%           |



## IPID Value Prediction (called IPID-TSF)
We introduce an IPID prediction approach that enables the learning of the historical changing behavior of an IPID counter to predict its future IPID values. This work mainly focuses on IPID prediction in IPv4.
Our IPID value prediction approach relies on machine learning regression models and involves forecasting a specific IPID time series originating from a tested host with global counters.

### Its working process is shown below:

1. For a given server, IPID-TSF collects IPID values by alternately sending one probe at each time point (e.g., per second) using two source addresses.
2. We utilize a sliding window with a size of 5 to learn historical IPID values. The sliding window is initialized by appending IPID values sampled until it reaches its maximum capacity.
3. We fill in missing values in IPID time series within the window if applicable.
4. We remove trends and periodicity when the IPID time series contains.
5. We employ a Gaussian Process (GP) model to fit historical IPID data within the window and forecast the IPID value for the next time point.
6. We enable continuous updating of the model with new data by removing the first (oldest) value in the window and adding the new value at the end for the next prediction.

## Z-test
We assume that prediction errors generated by the predictive (GP) model follow a Gaussian distribution, as evidenced by previous studies, such as [2], [3], [4].

Given N IPID predictions for a counter, we obtain the prediction errors $E = e_{n}, n \in [0, N-1]$, where $e_{n}=\hat{x_{n}}-x_{n}$, with $\hat{x_{n}}$ and $x_{n}$ representing the predicted and actual values at the ${n}_{th}$ second, respectively.

We then compute the mean and the standard deviation of $E$, denoted as $\mu$ and $\sigma$.
Since $E$ follows a Gaussian distribution, the variable Z = $\frac{E-\mu}{\sigma}$ conforms to the standard normal distribution of $N(0,1)$.


Suppose we send a certain number of spoofed packets, denoted as $n_{s}$, within the N-second interval.
When successful perturbations on the counter occur, it causes the value of $e_{N}$ to decrease.
As a result, the $e_{N}$ value would fall in the left tail of the distribution.
We conduct a left-tailed Z-test with a significance level of $\alpha$ = 0.05 to identify anomalous IPID value increases resulting from spoofed packets.

Next, we present a theoretical deduction of the minimum number of spoofed packets required to perturb the counter.
There is $\Phi (\frac{e_{N}-\mu}{\sigma}) < \alpha$ in the case of
successful IPID perturbation, with $e_{N} = \hat{x_{N}}-(x_{N}+n_{s})$.

Then we derive the value of $n_{s}$ as follows: 
    $\frac{e_{N}-\mu}{\sigma} < \Phi ^{-1}(\alpha)$
    $n_{s} >  -\Phi ^{-1}(\alpha)*\sigma - \mu + \hat{x_{N}}-x_{N}\end{aligned}$

We use $e_{max}$, the maximum prediction error in $E$, as the estimated
value of $\tilde{e}_{N}$ (which equals $\hat{x}_{N}-x_{N}$, with the
ideal value being 0) to yield a relatively large $n_{s}$ value, ensuring
the triggering of the anomaly detection. We also ensure that we send at
least one spoofed packet. Then, we define
$n_{s} = 1 + (-\Phi ^{-1}(\alpha)*\sigma - \mu + e_{max})$.
