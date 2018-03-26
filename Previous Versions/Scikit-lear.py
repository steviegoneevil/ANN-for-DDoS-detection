'''
Created on 18 Jan 2018

@author: Stephen
'''
import pandas
from sklearn.datasets import load_breast_cancer
#cancer = load_breast_cancer()
data = pandas.read_csv('test.csv', delimiter=',')

data = data._get_numeric_data()
print(data)
print(data.keys())
print(data[['Packet','Packets/Time']])
print(data['target'])

X = data[['Packet','Packets/Time']]
y = data['target']

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
X_train, X_test, y_train, y_test = train_test_split(X, y)
scaler = StandardScaler()

scaler.fit(X_train)
X_train = scaler.transform(X_train)
X_test = scaler.transform(X_test)

from sklearn.neural_network import MLPClassifier

mlp = MLPClassifier(hidden_layer_sizes=(10))
mlp.fit(X_train, y_train)

predictions = mlp.predict(X_test)

from sklearn.metrics import classification_report,confusion_matrix
print(confusion_matrix(y_test,predictions))
print (classification_report(y_test,predictions))
print(mlp.coefs_)
print(mlp.intercepts_)