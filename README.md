!# ZPredict
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

### Outputs: MAE, RMSE, and SMAPE
IPID-TSF has three outputs, which represent the prediction errors of a predictive model on an IPID time series, including the mean absolute error (MAE), the root mean square error (RMSE), the symmetric mean absolute percentage error (SMAPE).

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
1. $\frac{e_{N}-\mu}{\sigma} < \Phi ^{-1}(\alpha)$
2. $n_{s} >  -\Phi ^{-1}(\alpha)*\sigma - \mu + \hat{x_{N}}-x_{N}$

We use $e_{max}$, the maximum prediction error in $E$, as the estimated
value of $\hat{x_{N}}-x_{N}$, with the
ideal value being 0) to yield a relatively large $n_{s}$ value, ensuring
the triggering of the anomaly detection. We also ensure that we send at
least one spoofed packet. Then, we define
$n_{s} = 1 + (-\Phi ^{-1}(\alpha)*\sigma - \mu + e_{max})$.

### Noting that during real-world measurements, to mitigate potential harm to the tested networks or servers, the test will terminate if the number of required spoofed packets exceeds 1000.

## Approach Validation
We conduct experiments to verify the effectiveness of our approach in identifying the IPID increase caused by spoofed packets.

In scenarios involving idle port scan and SAV measurement, tools like Nmap [5] and SMap [6] detect global IPID increments resulting from spoofed packets at a single time point. In contrast, techniques for censorship assessment or related studies, such as Augur [7] and Ensafi [8], analyze at least two IPID increments, taking into account potential TCP retransmissions.

We generate various datasets of IPID time series, simulating distinct scenarios in port scanning/SAV inference and censorship measurement.
These datasets comprise IPID time series with no IPID increments induced by spoofed packets, with a single IPID increment, or with two IPID increments: one arising from the initial spoofed packets and the other from the SYN ACK retransmission.

We collect IPID time series from 5,000 randomly selected hosts with global IPID counters, disregarding their predictability.

Assuming that the first retransmission timeout (RTO) is 3s.
We make 30 predictions for IPID time series from a specific host before spoofed packet injection.
To ensure the collected time series is long enough to cover two IPID increments driven by spoofed packets, we send 39 probes to the 5,000 servers at a rate of one packet per second. 

Afterward, we generate new datasets based on the initial data for experiments.
Assuming that we send spoofed packets within the $35^{th}$ second, the induced IPID increment (e.g., in cases of open ports) would occur at the $35^{th}$ second.
However, in censorship measurement, when the censor device is deployed in the outbound direction, it triggers TCP retransmission, resulting in the second IPID increment. As mentioned earlier, we assume that the first RTO value is 3s. The second increment would occur at the $38^{th}$ second.

We estimate the number of spoofed packets ($n_{s}$) using the formula: $n_{s} = 1 + (-\Phi ^{-1}(\alpha)*\sigma - \mu + e_{max})$.
Since our experiments are conducted on offline data, there is no need to limit the value of $n_{s}$.

Initially, we synthesize a dataset by incrementing the IPID value by $n_{s}$ from the $35^{th}$ second to the end for each time series in the initial dataset.
Subsequently, based on this synthesized dataset, we generate another new dataset by increasing the IPID value by $n_{s}$ at the $38^{th}$ second, ensuring each IPID time series in this set contains two IPID increases.

We then proceed to verify the effectiveness of our approach in identifying IPID increases across various scenarios. For this purpose, we utilize both the initial dataset and the dataset containing a single IPID increment to assess its performance in port scanning or SAV assessment. Additionally, all three datasets are employed to examine the validity in censorship measurement. 

![Fig. \ref{fig:port_scan_fpr_fnr}](images/port_scan_fpr_fnr_plot.pdf) illustrates false positive rates (FPR) and false negative rates (FNR) varying across different MAE, RMSE, and SMAPE values
in the context of port scanning or SAV inference. In port scanning, the FPR denotes the rate of mistakenly identifying closed ports as open, while in SAV inference, it indicates the rate at which non-IP-spoofable networks are falsely classified as IP-spoofable.

Each data point, represented by (MAE/RMSE/SMAPE, FPR/FNR), showcases the corresponding FPR/FNR value under the condition that the prediction error of IPID time series is lower than the corresponding MAE/RMSE/SMAPE value. Notably, we observe a convergence of FPR and FNR values to around 8% and 5%, respectively, as the MAE, RMSE, and SMAPE values increase.

![Fig. \ref{fig:censor_measure_accs}](images/censor_measure_accs_plot.pdf) and ![Fig. \ref{fig:censor_measure_fpr_fnr}](images/censor_measure_fpr_fnr_plot.pdf) illustrate the validation results using datasets associated with censor measurement, including accuracy values across three states: "No blocking", "Ingress blocking", and "Egress blocking", as well as the false positive rate (FPR) and false negative rate (FNR) values.
In this context, the FPR is defined as the rate at which networks without deploying censor devices are incorrectly identified as having censorship deployment.

### Noting that, during real-world measurements, multiple measurements (e.g., 5 times) are performed to reduce false positive and false negative rates.

