# ANN-for-DDoS-detection

## Prerequisites

Download & Install Python 3.6 64-bit https://www.python.org/downloads/ (Make sure you add it to PATH)

Download and install Wireshark (Make sure Tshark and WinPcap are installed aswell)

## Installation

Clone this repository to desired location

Open CMD

'cd' to repository location

use the following line in CMD to install the necessary requirements "pip install -r requirements.txt"

## Starting Off

Open CMD

'cd' to repository location

python ProjectANNv9.py

Inpur number between 1-7, depending on what you would like to do

### 1 - Packet Sniffer
This is a basic packet sniffer

From the list, input the name of the inetrface you wish to sniff
Packet information should now be seen
ctrl + c to cancel

### 2 - ANN Data gatherer
This is used to create a dataset to train and test an ANN.

From the list, input the name of the inetrface you wish to gather data from
ctrl + c to cancel

### 3 - Neural Netwrok Trainer
Creates and trains an ANN from a dataset

input name of the CSV dataset file you wish to use
If you want to load a previous model, input 'y' and then input the name of the model
Else just hit Enter
Depending on model tpology and the size of the dataset, the process may take a while
ONce finished, input 'y' to see the Weights and intercepts of the model after training
input 'y' again to save the model (Must end in '.sav') 

### 4 - Data viewer
Allows for viewing the data within a dataset

input name of CSV Dataset you wish to view
input 'a' to see All, 'n' to see just the numerical data, 'c' to see just categorical data

### 5 - Live Neural Network
Uses a trained ANN to detect DDoS Attacks

From the list, input the name of the inetrface you wish to detect DDoS attacks on
input the filename of a trained model
This will continuously run until either stopped or an attack is detected

### 6 - Visual ANN
Shows a visual representation of what an ANN model looks like (Can be changed in code, currently displays an input layer of 8, 2 hidden layers of 100 and an output layer of 1.

### 7 - Exit


