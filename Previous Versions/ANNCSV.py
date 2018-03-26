'''
Created on 6 Feb 2018

@author: Stephen
'''
from io import StringIO
import numpy as np
import pandas
import csv

data = pandas.read_csv('test.csv', delimiter=',')
headers = list(data.columns.values)
print(headers)

data = data._get_numeric_data()

print(data.keys())
print(data.shape)
print(data)

