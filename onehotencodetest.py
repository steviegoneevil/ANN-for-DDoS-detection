'''
Created on 9 Feb 2018

@author: Stephen
'''
from io import StringIO
import winreg # to use windows registry to ID guids given by netifaces
import netifaces # used to identify netwrok interafces on a system and returning the ocrresponding guid
import pickle # used to save the model for further testing and use
import csv #python standard for csv work
import pyshark # tshark wrapper used to capture and parse packets
import sys
import time
import datetime
import pandas # data handler
from pyshark import packet
from builtins import int
from pprint import pprint
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import matthews_corrcoef
import pyshark
from timeit import default_timer as timer
from sklearn.metrics.classification import matthews_corrcoef
from sklearn.preprocessing import LabelEncoder



def main():

main()