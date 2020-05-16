
# coding: utf-8

# In[10]:

#importing libraries
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.externals import joblib


# In[11]:

#importing the dataset
dataset = pd.read_csv("G:\VIT\PROJECT\PROJECT\DATASET\TrainingDataset.csv")


# In[12]:

dataset = dataset.drop('id', 1) #removing unwanted column
x = dataset.iloc[ : , :-1].values
y = dataset.iloc[:, -1:].values


# In[13]:

#spliting the dataset into training set and test set
from sklearn.cross_validation import train_test_split
x_train, x_test, y_train, y_test = train_test_split(x,y,test_size = 0.25, random_state =0 )


# In[19]:

#fitting logistic regression 
classifier = LogisticRegression(random_state = 0)
classifier.fit(x_train, y_train)


# In[20]:

#predicting the tests set result
y_pred = classifier.predict(x_test)


# In[21]:

#confusion matrix
from sklearn.metrics import confusion_matrix
cm = confusion_matrix(y_test, y_pred)
print(cm)


# In[25]:

scr = classifier.score(x_test, y_test)
print("Score :",scr)


# In[26]:

#pickle file joblib
joblib.dump(classifier, 'G:\VIT\PROJECT\PROJECT\pickle\LR.pkl')

