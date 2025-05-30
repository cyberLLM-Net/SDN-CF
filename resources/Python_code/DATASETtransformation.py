import pandas as pd
import numpy as np
from sklearn import metrics
from sklearn.feature_selection import RFECV
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, classification_report, confusion_matrix
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.feature_selection import RFECV
from sklearn.tree import DecisionTreeClassifier
import sys

# Seed initialization
np_random_seed = 2
np.random.seed(2)

# Loading the datasets separately
dataset_metasploit = pd.read_csv(r"Dataset\metasploitable-2.csv")
print("Number of rows in the Metasploit dataset containing anomalous data")
print(len(dataset_metasploit.index))
dataset_normalData = pd.read_csv(r"Dataset\normal_data.csv")
print("Number of rows in normal data")
print(len(dataset_normalData.index))
print("Data loaded")

# Merging the 3 datasets into a single one
dataset = [dataset_metasploit, dataset_normalData]
dataset_total = pd.concat(dataset, ignore_index=True)
print("Number of merged rows")
print(len(dataset_total.index))

# We change the "Label" feature to assign a numeric value.
# 1 for attack traffic
# 0 for normal traffic
cleanup_nums = {"Label": {"Normal": 0, "Probe": 1, "DDoS": 1, "DoS": 1, "BFA": 1, "Web-Attack": 1, "BOTNET": 1, "U2R": 1, "DDoS ": 1}}
dataset_total_filtered = dataset_total.replace(cleanup_nums)

# Removing features with constant values across all rows and the identifier (NaN values in the correlation matrix) -> Reviewed
dt_not_NaN = dataset_total_filtered.drop(['Flow ID', 'Fwd PSH Flags', 'Fwd URG Flags', 'CWE Flag Count', 'ECE Flag Cnt',
                                          'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
                                          'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Init Fwd Win Byts', 'Fwd Seg Size Min'], axis=1)
                                          
# Creation of variables based on the destination subnet
dt_new = dt_not_NaN
dt_new['Dst 192.168.8'] = np.where(dt_new["Dst IP"].str.startswith('192.168.8.'), 1, 0)     # ONOS and Mininet
dt_new['Dst 192.168.3.'] = np.where(dt_new["Dst IP"].str.startswith('192.168.3.'), 1, 0)    # Metasploitable and Mininet
dt_new['Dst 200.175.2.'] = np.where(dt_new["Dst IP"].str.startswith('200.175.2.'), 1, 0)    # Kali and Mininet
dt_new['Dst 192.168.20.'] = np.where(dt_new["Dst IP"].str.startswith('192.168.20.'), 1, 0)  # Internal Mininet machines
dt_new['Dst 172.17.0.'] = np.where(dt_new["Dst IP"].str.startswith('172.17.0.'), 1, 0)      # DVWA

# Creation of variables based on the source subnet
dt_new['Src 192.168.3.'] = np.where(dt_new["Src IP"].str.startswith('192.168.3.'), 1, 0)    # Metasploitable and Mininet
dt_new['Src 200.175.2.'] = np.where(dt_new["Src IP"].str.startswith('200.175.2.'), 1, 0)    # Kali and Mininet
dt_new['Src 192.168.20.'] = np.where(dt_new["Src IP"].str.startswith('192.168.20.'), 1, 0)  # Internal Mininet machines
dt_new['Src 172.17.0.'] = np.where(dt_new["Src IP"].str.startswith('172.17.0.'), 1, 0)      # DVWA

# Cleaning variables that will not be used
dt_new = dt_new.drop(['Src IP', 'Dst IP', 'Timestamp'], axis=1)

# Cleaning negative values in the Flow Duration field
negative_index = dt_new.index[dt_new['Flow Duration'] < 0]
dt_new = dt_new.drop(negative_index)

# Isolation_Forest
# Cases to eliminate
# 1 Variable 1 -> 'Flow Duration' values that are too high
# 2 Variable 2 -> 'Flow IAT Std', 'Fwd IAT Std', 'Flow IAT Max', and 'Fwd IAT Tot' values that are too high
# 3 Variable 3 -> Very high values of 'Bwd IAT Tot'
# 4 Variable 4 -> Very high values of 'Pkt Len Max'

dt_new_delete_outliers = dt_new

variable1=['Flow Duration', 'Tot Fwd Pkts','Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max','Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std','Bwd Pkt Len Max', 'Bwd Pkt Len Min']
variable2=['Bwd Pkt Len Mean','Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean','Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot','Fwd IAT Mean', 'Fwd IAT Std']
variable3=['Fwd IAT Max', 'Fwd IAT Min','Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max','Bwd IAT Min', 'Bwd PSH Flags', 'Bwd URG Flags', 'Fwd Header Len','Bwd Header Len']
variable4=['Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Min','Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var','FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt']
variable5=['ACK Flag Cnt', 'URG Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg','Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Subflow Fwd Pkts','Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts','Init Bwd Win Byts']
variable6=['Fwd Act Data Pkts', 'Active Mean', 'Active Std','Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max','Idle Min']

model=IsolationForest(n_estimators=50, max_samples='auto', contamination=0.0001,max_features=8, random_state=1)

model.fit(dt_new_delete_outliers[variable1])
dt_new_delete_outliers['anomaly']=model.predict(dt_new_delete_outliers[variable1])
anomaly=dt_new_delete_outliers.loc[dt_new_delete_outliers['anomaly']==-1]
anomaly_index=list(anomaly.index)
dt_new = dt_new.drop(anomaly_index)

model.fit(dt_new_delete_outliers[variable2])
dt_new_delete_outliers['anomaly']=model.predict(dt_new_delete_outliers[variable2])
anomaly=dt_new_delete_outliers.loc[dt_new_delete_outliers['anomaly']==-1]
anomaly_index=list(anomaly.index)
dt_new = dt_new.drop(anomaly_index)

model.fit(dt_new_delete_outliers[variable3])
dt_new_delete_outliers['anomaly']=model.predict(dt_new_delete_outliers[variable3])
anomaly=dt_new_delete_outliers.loc[dt_new_delete_outliers['anomaly']==-1]
anomaly_index=list(anomaly.index)
dt_new = dt_new.drop(anomaly_index)

model.fit(dt_new_delete_outliers[variable4])
dt_new_delete_outliers['anomaly']=model.predict(dt_new_delete_outliers[variable4])
anomaly=dt_new_delete_outliers.loc[dt_new_delete_outliers['anomaly']==-1]
anomaly_index=list(anomaly.index)
dt_new = dt_new.drop(anomaly_index)

dt_new= dt_new.drop(['anomaly'], axis=1)

# END - Isolation_Forest

# Variables with very high correlation

# Flow Duration -> Duration of the flow in microseconds
# ------ Bwd IAT Tot - 0.98 -> Total time between 2 packets sent in the backward direction
# This is removed because it has lower correlation with the label (0.01)
dt_new = dt_new.drop(['Bwd IAT Tot'], axis=1)

# Tot Fwd Pkts -> Number of packets in the forward direction
# ------ Subflow Fwd Pkts - 1.00 -> Average number of packets in forward subflow
# Same value, indifferent
dt_new = dt_new.drop(['Subflow Fwd Pkts'], axis=1)

# TotLen Fwd Pkts -> Total size of packets in the forward direction
# ------ Subflow Fwd Byts - 0.99 -> Average number of bytes in forward subflow
# Same value, indifferent
dt_new = dt_new.drop(['Subflow Fwd Byts'], axis=1)

# TotLen Bwd Pkts -> Total size of packets in the backward direction
# ------ Subflow Bwd Byts - 0.99 -> Average number of bytes in backward subflow
# Same value, indifferent
dt_new = dt_new.drop(['Subflow Bwd Byts'], axis=1)

# Tot Bwd Pkts -> Number of packets in the backward direction
# ------ Bwd Header Len - 0.99 -> Number of bytes used for headers in the backward direction
# ------ Subflow Bwd Pkts - 1.00 -> Average number of packets in backward subflow
dt_new = dt_new.drop(['Bwd Header Len'], axis=1)
dt_new = dt_new.drop(['Subflow Bwd Pkts'], axis=1)

# Fwd Pkt Len Mean -> Average packet size in the forward direction
# ------ Fwd Pkt Len Std - 0.954 -> Standard deviation of packet size in forward direction
# ------ Fwd Seg Size Avg - 1.00 -> Average segment size in the forward direction
dt_new = dt_new.drop(['Fwd Pkt Len Std'], axis=1)
dt_new = dt_new.drop(['Fwd Seg Size Avg'], axis=1)

# Bwd Pkt Len Max -> Maximum packet size in the backward direction
# ------ Pkt Len Max - 0.97 -> Maximum size of a packet
dt_new = dt_new.drop(['Bwd Pkt Len Max'], axis=1)

# Bwd Pkt Len Mean -> Average packet size in the backward direction
# ------ Bwd Seg Size Avg - 1.0000 -> Average bulk byte rate observed in the backward direction
dt_new = dt_new.drop(['Bwd Seg Size Avg'], axis=1)

# Flow Pkts/s -> Flow packets per second
# ------ Bwd Pkts/s - 0.99 -> Number of backward packets per second
dt_new = dt_new.drop(['Flow Pkts/s'], axis=1)

# Flow IAT Std -> Standard deviation of time between 2 packets sent in the flow
# ------ Flow IAT Max - 0.98 -> Maximum time between 2 packets sent in the flow
# ------ Bwd IAT Std - 0.98 -> Average time between 2 packets in the backward direction
# ------ Bwd IAT Max - 0.97 -> Maximum time between 2 packets in the backward direction
# ------ Idle Mean - 0.98 -> Mean idle time before the flow became active
# ------ Idle Max - 0.98 -> Maximum idle time before the flow became active
# ------ Idle Min - 0.98 -> Minimum idle time before the flow became active

dt_new= dt_new.drop(['Flow IAT Std'], axis=1)
dt_new= dt_new.drop(['Flow IAT Max'], axis=1)
dt_new= dt_new.drop(['Bwd IAT Max'], axis=1)
dt_new= dt_new.drop(['Idle Mean'], axis=1)
dt_new= dt_new.drop(['Idle Max'], axis=1)
dt_new= dt_new.drop(['Idle Min'], axis=1)


# Bwd PSH Flags -> Number of times the PSH flag was used in backward direction packets
# ------ PSH Flag Cnt - 1 -> Number of packets with the PSH flag
dt_new = dt_new.drop(['Bwd PSH Flags'], axis=1)

# Bwd URG Flags -> Number of times the URG flag was used in backward direction packets
# ------ URG Flag Cnt - 1 -> Number of packets with the URG flag
dt_new = dt_new.drop(['URG Flag Cnt'], axis=1)

# Pkt Len Mean -> Mean packet size
# ------ Pkt Len Std - 0.96 -> Standard deviation of packet size
# ------ Pkt Size Avg - 0.99 -> Average packet size
dt_new = dt_new.drop(['Pkt Len Mean'], axis=1)
dt_new = dt_new.drop(['Pkt Len Std'], axis=1)

# RFECV (Recursive Feature Elimination with Cross-Validation)
target = dt_new['Label']
X = dt_new.drop('Label', axis=1)
rfc = DecisionTreeClassifier(random_state=0)

# Execute RFECV
rfecv = RFECV(estimator=rfc, step=1, cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=3), 
              scoring='accuracy', verbose=4, min_features_to_select=1)
rfecv.fit(X, target)

# Get the number of selected features
print('Optimal number of features: {}'.format(rfecv.n_features_))
print("Features to NOT select")
print(np.where(rfecv.support_ == False)[0])
print("Features to select")
print(np.where(rfecv.support_ == True)[0])
X.drop(X.columns[np.where(rfecv.support_ == False)[0]], axis=1, inplace=True)
selected_columns = X.columns.tolist()
selected_columns.append('Label')
dt_new = dt_new[selected_columns]

# END - RFECV
# Resetting the indices to allow proper indexing
dt_new.reset_index(inplace=True, drop=True)

print("Final number of rows")
print(len(dt_new.index))

dt_new.to_csv(r"dataset.csv", encoding='utf-8', index=False)
print("Dataset saved")


