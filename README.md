
# Classifier with ONOS API (SDN-CF)

## SDN Application
In the */onoscf* folder, we have the Java project of the SDN application that is installed on the ONOS Controller and carries out the detection and blocking of attack traffic.

## Resources
In the */resources* folder, you can find various project resources:
- In */Python_code*, there are a Python program (`DATASETtransformation.py`) for transforming the datasets, preparing them, selecting features, and generating dataset files.
- In */target*, you can find the dataset for training classifier (`dataset.arff`) and the APP in OAR format (`packetprocess-2.0.0.oar`), which must be installed on the controller to launch the packet classifier.
- Finally, this folder contains the necessary Weka libraries to use the classifiers within the Karaf bundle (`weka-stable_3.8.0.jar`).