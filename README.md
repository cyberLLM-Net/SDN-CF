# Classifier with ONOS API (SDN-CF)

## SDN Application

In the `*/onoscf*` folder, you will find the Java project for the SDN application deployed on the ONOS Controller. This application is responsible for detecting and blocking malicious network traffic.

The source code is structured into cohesive Java packages, each dedicated to a specific functionality within the application. The following components represent the main building blocks of the class model:

- **`FlowKey`, `FlowData`**: These classes handle the identification and characterization of network flows. They model the essential attributes of a flow (e.g., source and destination IP addresses, ports, and protocols) and provide the data structures used throughout the processing pipeline.

- **`ValueFlowFeature`, `DistributionFlowFeature`**: These classes implement the feature extraction mechanisms. `ValueFlowFeature` focuses on computing direct flow statistics, such as packet counts and byte volumes, while `DistributionFlowFeature` calculates statistical distributions over flow attributes, such as inter-arrival times and size variance.

- **`CsvExporter`**: This utility class manages the export of flow data and extracted features to annotated CSV files. These files can be used for training machine learning models or for offline analysis.

- **`RandomForestClassifier`**: This component encapsulates a Random Forest model trained on labeled flow data. It is used to predict whether a given flow is malicious or benign, and it can be replaced or extended to support other classifiers.

- **`PacketProcess`**: This is the core processing unit of the application. It directly interfaces with the ONOS controller’s packet pipeline, intercepts incoming traffic, performs feature extraction and classification, and enforces mitigation policies based on the prediction results.

## Resources

In the `*/resources*` folder, you will find various project resources:

- Inside `*/Python_code*`, there is a Python script (`DATASETtransformation.py`) for transforming datasets, preparing them, selecting features, and generating dataset files.

- Inside `*/target*`, you will find the dataset used to train the classifier (`dataset.arff`) and the application packaged in OAR format (`packetprocess-2.0.0.oar`), which must be installed on the controller to activate the packet classifier.

- Finally, this folder contains the necessary Weka libraries for running classifiers within the Karaf runtime (`weka-stable_3.8.0.jar`).
