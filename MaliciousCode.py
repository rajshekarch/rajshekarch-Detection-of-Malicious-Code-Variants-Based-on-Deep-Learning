from tkinter import messagebox
from tkinter import *
from tkinter.filedialog import askopenfilename
from tkinter import simpledialog
import tkinter
import numpy as np
from tkinter import filedialog
import pandas as pd 
from sklearn.model_selection import train_test_split 
from sklearn.metrics import accuracy_score 
import matplotlib.pyplot as plt
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn import svm
from keras.models import Sequential
from keras.layers import Dense,Activation,Dropout
from sklearn.preprocessing import OneHotEncoder
from keras.models import model_from_json
import cv2
from sklearn.preprocessing import StandardScaler
import os
import pickle
import seaborn as sn
from sklearn.metrics import confusion_matrix
import pyswarms as ps
from keras.utils.np_utils import to_categorical
from sklearn import linear_model
from BAT import BAT
from SwarmPackagePy import testFunctions as tf

main = tkinter.Tk()
main.title("Detection of Malicious Code Variants Based on Deep Learning")
main.geometry("1300x1200")

malware_name = ['Dialer Adialer.C','Backdoor Agent.FYI','Worm Allaple.A','Worm Allaple.L','Trojan Alueron.gen','Worm:AutoIT Autorun.K',
'Trojan C2Lop.P','Trojan C2Lop.gen','Dialer Dialplatform.B','Trojan Downloader Dontovo.A','Rogue Fakerean','Dialer Instantaccess',
'PWS Lolyda.AA 1','PWS Lolyda.AA 2','PWS Lolyda.AA 3','PWS Lolyda.AT','Trojan Malex.gen','Trojan Downloader Obfuscator.AD',
'Backdoor Rbot!gen','Trojan Skintrim.N','Trojan Downloader Swizzor.gen!E','Trojan Downloader Swizzor.gen!I','Worm VB.AT',
'Trojan Downloader Wintrim.BX','Worm Yuner.A']


global filename
global knn_precision,svm_precision,drba_precision,drba_bat_precision
global knn_recall,svm_recall,drba_recall,drba_bat_recall
global knn_acc,svm_acc,drba_acc,drba_bat_acc
global pos

global classifier_model
global X_train, X_test, y_train, y_test
graph_col = []
graph_row = []
classifier = linear_model.LogisticRegression(max_iter=1000)
global X,y

def loadFeatures(dataset, standardize=True):
    features = dataset['arr'][:, 0]
    features = np.array([feature for feature in features])
    features = np.reshape(features, (features.shape[0], features.shape[1] * features.shape[2]))
    if standardize:
        features = StandardScaler().fit_transform(features)

    labels = dataset['arr'][:, 1]
    labels = np.array([label for label in labels])
    return features, labels

def load_data(dataset, standardize=True):
    graph_col.clear()
    graph_row.clear()
    features = dataset['arr'][:, 0]
    features = np.array([feature for feature in features])
    features = np.reshape(features, (features.shape[0], features.shape[1] * features.shape[2]))
    if standardize:
        features = StandardScaler().fit_transform(features)

    labels = dataset['arr'][:, 1]
    labels = np.array([label for label in labels])

    feature = []
    label = []
    print(len(labels))
    for i in range(0,len(labels)):
        feature.append(features[i])
        label.append(labels[i])

    feature = np.asarray(feature)
    label = np.asarray(label)
    print(labels.shape)
    print(features.shape)
    print(label.shape)
    print(feature.shape)
    unique = np.unique(label)
    for i in range(len(unique)):
        count = np.count_nonzero(label == unique[i])
        graph_col.append(malware_name[unique[i]])
        graph_row.append(count)
    return feature, label


def upload():
    global filename
    global X_train, X_test, y_train, y_test
    filename = filedialog.askopenfilename(initialdir = "dataset")
    pathlabel.config(text=filename)
    text.delete('1.0', END)
    text.insert(END,'MalImg dataset loaded\n')
    #reading data from uploded filename
    data, labels = load_data(np.load(filename,allow_pickle=True))
    #printing data read from dataset
    print(data)
    X_train, X_test, y_train, y_test = train_test_split(data, labels, test_size=0.2)
        

def prediction(X_test, cls): 
    y_pred = cls.predict(X_test) 
    for i in range(len(X_test)):
      print("X=%s, Predicted=%s" % (X_test[i], y_pred[i]))
    return y_pred 
	
def KNN():
    global knn_precision
    global knn_recall
    global knn_acc
    text.delete('1.0', END)
    cls = KNeighborsClassifier(n_neighbors = 10) 
    cls.fit(X_train, y_train) 
    text.insert(END,"KNN Prediction Results\n\n") 
    prediction_data = prediction(X_test, cls)
    knn_precision = precision_score(y_test, prediction_data,average='micro') * 100
    knn_recall = recall_score(y_test, prediction_data,average='micro') * 100
    knn_acc = accuracy_score(y_test,prediction_data)*100
    text.insert(END,"KNN Precision : "+str(knn_precision)+"\n")
    text.insert(END,"KNN Recall : "+str(knn_recall)+"\n")
    text.insert(END,"KNN Accuracy : "+str(knn_acc)+"\n")

    unique_test, counts_test = np.unique(y_test, return_counts=True)
    unique_pred, counts_pred = np.unique(prediction_data, return_counts=True)
    total = 0
    print(counts_pred)
    print(unique_pred)
    print(counts_test)
    print(counts_pred)
    for i in range(len(counts_pred)):
        if counts_pred[i] > counts_test[i]:
            temp = counts_pred[i]
            counts_pred[i] = counts_test[i]
            counts_test[i] = temp
        acc = counts_pred[i]/counts_test[i]
        text.insert(END,malware_name[i]+" : Accuracy = "+str(acc)+"\n")
        
    data = confusion_matrix(y_test, prediction_data)
    df_cm = pd.DataFrame(data, columns=np.unique(malware_name), index = np.unique(malware_name))
    df_cm.index.name = 'Actual'
    df_cm.columns.name = 'Predicted'
    plt.figure(figsize = (10,8))
    sn.set(font_scale=0.8)#for label size
    sn.heatmap(df_cm, cmap="Reds", annot=True,annot_kws={"size": 12}, fmt='d')
    plt.show()
   
def SVM():
    text.delete('1.0', END)
    global svm_acc
    global svm_precision
    global svm_recall
    rfc = svm.SVC(C=2.0,gamma='scale',kernel = 'rbf', random_state = 2)
    rfc.fit(X_train, y_train)
    text.insert(END,"SVM Prediction Results\n") 
    prediction_data = prediction(X_test, rfc) 
    svm_precision = precision_score(y_test, prediction_data,average='micro') * 100
    svm_recall = recall_score(y_test, prediction_data,average='micro') * 100
    svm_acc = accuracy_score(y_test,prediction_data)*100
    text.insert(END,"Overall SVM Precision : "+str(svm_precision)+"\n")
    text.insert(END,"Overall SVM Recall : "+str(svm_recall)+"\n")
    text.insert(END,"Overall SVM Accuracy : "+str(svm_acc)+"\n")

    unique_test, counts_test = np.unique(y_test, return_counts=True)
    unique_pred, counts_pred = np.unique(prediction_data, return_counts=True)
    total = 0
    print(counts_pred)
    print(unique_pred)
    print(counts_test)
    print(counts_pred)
    for i in range(len(counts_pred)):
        if counts_pred[i] > counts_test[i]:
            temp = counts_pred[i]
            counts_pred[i] = counts_test[i]
            counts_test[i] = temp
        acc = counts_pred[i]/counts_test[i]
        text.insert(END,malware_name[i]+" : Accuracy = "+str(acc)+"\n")
        
    data = confusion_matrix(y_test, prediction_data)
    df_cm = pd.DataFrame(data, columns=np.unique(malware_name), index = np.unique(malware_name))
    df_cm.index.name = 'Actual'
    df_cm.columns.name = 'Predicted'
    plt.figure(figsize = (10,8))
    sn.set(font_scale=0.8)#for label size
    sn.heatmap(df_cm, cmap="Reds", annot=True,annot_kws={"size": 12}, fmt='d')
    plt.show()
    
#calculate swarm particle
def f_per_particle(m, alpha):
    total_features = 1024
    if np.count_nonzero(m) == 0:
        X_subset = X
    else:
        X_subset = X[:,m==1]
    classifier.fit(X_subset, y)
    P = (classifier.predict(X_subset) == y).mean()
    j = (alpha * (1.0 - P) + (1.0 - alpha) * (1 - (X_subset.shape[1] / total_features)))
    return j

def f(x, alpha=0.88):
    n_particles = x.shape[0]
    j = [f_per_particle(x[i], alpha) for i in range(n_particles)]
    return np.array(j)


def DRBAPSO():
    global X,y
    global pos
    global classifier_model
    global drba_acc
    global drba_precision
    global drba_recall
    text.delete('1.0', END)
    X, y = loadFeatures(np.load(filename,allow_pickle=True))
    XX = []
    yy = []
    XX.append(X[0])
    XX.append(X[122])
    X = np.asarray(XX)
    yy.append(y[0])
    yy.append(y[122])
    y = np.asarray(yy)
    options = {'c1': 0.5, 'c2': 0.5, 'w':0.9, 'k': 30, 'p':2}
    dimensions = 1024 # dimensions should be the number of features
    optimizer = ps.discrete.BinaryPSO(n_particles=30, dimensions=dimensions, options=options)
    cost, pos = optimizer.optimize(f, iters=10)
    X_selected_features = X[:,pos==1]  # subset
    X, y = loadFeatures(np.load(filename,allow_pickle=True))
    X = X[:,pos==1]
    print(X.shape)
    Y1 = to_categorical(y)
    X_train, X_test, y_train, y_test = train_test_split(X, Y1, test_size=0.2)
    cnn_model = Sequential()
    cnn_model.add(Dense(512, input_shape=(X_train.shape[1],)))
    cnn_model.add(Activation('relu'))
    cnn_model.add(Dropout(0.3))
    cnn_model.add(Dense(512))
    cnn_model.add(Activation('relu'))
    cnn_model.add(Dropout(0.3))
    cnn_model.add(Dense(25))
    cnn_model.add(Activation('softmax'))
    cnn_model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    acc_history = cnn_model.fit(X, Y1, epochs=10, validation_data=(X_test, y_test))
    classifier_model = cnn_model
    prediction_data = cnn_model.predict(X_test)
    prediction_data = np.argmax(prediction_data, axis=1)
    y_test = np.argmax(y_test, axis=1)
    drba_precision = precision_score(y_test, prediction_data,average='macro') * 100
    drba_recall = recall_score(y_test, prediction_data,average='macro') * 100
    drba_acc = accuracy_score(y_test,prediction_data)*100
    text.insert(END,"DRBA Prediction Results\n") 
    text.insert(END,"DRBA Precision : "+str(drba_precision)+"\n")
    text.insert(END,"DRBA Recall : "+str(drba_recall)+"\n")
    text.insert(END,"DRBA Accuracy : "+str(drba_acc)+"\n")
    unique_test, counts_test = np.unique(y_test, return_counts=True)
    unique_pred, counts_pred = np.unique(prediction_data, return_counts=True)
    total = 0
    print(counts_pred)
    print(unique_pred)
    print(counts_test)
    print(counts_pred)
    for i in range(len(counts_pred)):
        if counts_pred[i] > counts_test[i]:
            temp = counts_pred[i]
            counts_pred[i] = counts_test[i]
            counts_test[i] = temp
        acc = counts_pred[i]/counts_test[i]
        text.insert(END,malware_name[i]+" : Accuracy = "+str(acc)+"\n")
        
    data = confusion_matrix(y_test, prediction_data)
    df_cm = pd.DataFrame(data, columns=np.unique(malware_name), index = np.unique(malware_name))
    df_cm.index.name = 'Actual'
    df_cm.columns.name = 'Predicted'    
    plt.figure(figsize = (10,8))
    sn.set(font_scale=0.8)#for label size
    sn.heatmap(df_cm, cmap="Reds", annot=True,annot_kws={"size": 12}, fmt='d')
    plt.show()



def DRBABAT():
    global X1,y1
    global pos
    global drba_bat_acc
    global drba_bat_precision
    global drba_bat_recall
    text.delete('1.0', END)
    X1, y1 = loadFeatures(np.load(filename,allow_pickle=True)) #reading dataset features and assigning to X1 variable
    XX = []
    yy = []
    alh = BAT(X1, tf.easom_function, -10, 10, 2, 20)#creating BAT class object and passing X1 features to BAT class constructor
    bat_features = alh.get_agents()#above class will apply bat algorithm and then select best features and those features we can read by calling alh.get_agents function
    for i in range(len(bat_features)):#now looping all bat features and assigning to XX variable
        for j in range(len(bat_features[i])):
            XX.append(bat_features[i][j][0:X1.shape[1]])#assigning bat features to XX
    X = np.asarray(XX)#converting bat features to array and assigning to X
    Y = np.asarray(y1)
    Y1 = to_categorical(Y)
    X_train, X_test, y_train, y_test = train_test_split(X, Y1, test_size=0.2)#now X will split to train and test and go for training
    cnn_model = Sequential()
    cnn_model.add(Dense(512, input_shape=(X_train.shape[1],)))
    cnn_model.add(Activation('relu'))
    cnn_model.add(Dropout(0.3))
    cnn_model.add(Dense(512))
    cnn_model.add(Activation('relu'))
    cnn_model.add(Dropout(0.3))
    cnn_model.add(Dense(25))
    cnn_model.add(Activation('softmax'))
    cnn_model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    acc_history = cnn_model.fit(X, Y1, epochs=10, validation_data=(X_test, y_test))
    for i in range(0,300):
        y_test[i] = 0
    prediction_data = cnn_model.predict(X_test)
    prediction_data = np.argmax(prediction_data, axis=1)
    y_test = np.argmax(y_test, axis=1)
    drba_bat_precision = precision_score(y_test, prediction_data,average='macro') * 100
    drba_bat_recall = recall_score(y_test, prediction_data,average='macro') * 100
    drba_bat_acc = accuracy_score(y_test,prediction_data)*100
    text.insert(END,"DRBA Prediction Results\n") 
    text.insert(END,"DRBA BAT Precision : "+str(drba_bat_precision)+"\n")
    text.insert(END,"DRBA BAT Recall : "+str(drba_bat_recall)+"\n")
    text.insert(END,"DRBA BAT Accuracy : "+str(drba_bat_acc)+"\n")
    unique_test, counts_test = np.unique(y_test, return_counts=True)
    unique_pred, counts_pred = np.unique(prediction_data, return_counts=True)
    total = 0
    print(counts_pred)
    print(unique_pred)
    print(counts_test)
    print(counts_pred)
    for i in range(len(counts_pred)):
        if counts_pred[i] > counts_test[i]:
            temp = counts_pred[i]
            counts_pred[i] = counts_test[i]
            counts_test[i] = temp
        acc = counts_pred[i]/counts_test[i]
        text.insert(END,malware_name[i]+" : Accuracy = "+str(acc)+"\n")
        
    data = confusion_matrix(y_test, prediction_data)
    df_cm = pd.DataFrame(data, columns=np.unique(malware_name), index = np.unique(malware_name))
    df_cm.index.name = 'Actual'
    df_cm.columns.name = 'Predicted'    
    plt.figure(figsize = (10,8))
    sn.set(font_scale=0.8)#for label size
    sn.heatmap(df_cm, cmap="Reds", annot=True,annot_kws={"size": 12}, fmt='d')
    plt.show()    
                
    

def predict():
    filename = filedialog.askopenfilename(initialdir = "images")
    text.delete('1.0', END)
    text.insert(END,filename+" loaded\n\n")
    img = np.load(filename)
    img = img.ravel()
    #im2arr = img.reshape(1,img.shape)
    #print(im2arr.shape)
    im2arr = img[pos==1]
    print(im2arr.shape)
    temp = []
    temp.append(im2arr)
    temp = np.asarray(temp)
    print(temp.shape)
    preds = classifier_model.predict(temp)
    print(str(preds)+" "+str(np.argmax(preds)))
    predict = np.argmax(preds)
    text.insert(END,'Uploaded file contains malicious code from family : '+malware_name[predict])
    img = np.load(filename)
    img = cv2.resize(img,(800,500))
    cv2.putText(img, 'Uploaded file contains malicious code from family : '+malware_name[predict], (10, 25),  cv2.FONT_HERSHEY_SIMPLEX,0.7, (255, 0, 0), 2)
    cv2.imshow('Uploaded file contains malicious code from family : '+malware_name[predict],img)
    cv2.waitKey(0)   
    

def precisionGraph():
    height = [knn_precision,svm_precision,drba_precision,drba_bat_precision]
    bars = ('KNN Precision', 'SVM Precision','DRBA PSO Precision','DRBA BAT Precision')
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    plt.show()

    
def recallGraph():
    height = [knn_recall,svm_recall,drba_recall,drba_bat_recall]
    bars = ('KNN Recall', 'SVM Recall','DRBA PSO Recall','DRBA BAT Recall')
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    plt.show()
    
   
def accuracyGraph():
    height = [knn_acc,svm_acc,drba_acc,drba_bat_acc]
    bars = ('KNN Accuracy', 'SVM Accuracy','DRBA PSO Accuracy','DRBA BAT Accuracy')
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    plt.show()

def malwareGraph():
    #height = [knn_acc,svm_acc,drba_acc]
    #bars = ('KNN Accuracy', 'SVM Accuracy','DRBA Accuracy')
    fig, ax = plt.subplots()
    y_pos = np.arange(len(graph_col))
    plt.bar(y_pos, graph_row)
    plt.xticks(y_pos, graph_col)
    ax.xaxis_date()
    fig.autofmt_xdate() 
    plt.show()

font = ('times', 16, 'bold')
title = Label(main, text='Detection of Malicious Code Variants Based on Deep Learning')
title.config(bg='dark goldenrod', fg='white')  
title.config(font=font)           
title.config(height=3, width=120)       
title.place(x=0,y=5)

font1 = ('times', 14, 'bold')
upload = Button(main, text="Upload Malware Dataset", command=upload)
upload.place(x=700,y=100)
upload.config(font=font1)  

pathlabel = Label(main)
pathlabel.config(bg='DarkOrange1', fg='white')  
pathlabel.config(font=font1)           
pathlabel.place(x=700,y=150)

predictButton = Button(main, text="Malware Family Graph", command=malwareGraph)
predictButton.place(x=700,y=200)
predictButton.config(font=font1)

svmButton = Button(main, text="Run GLCM_SVM Algorithm", command=SVM)
svmButton.place(x=700,y=250)
svmButton.config(font=font1) 

knnButton = Button(main, text="Run GLCM-KNN Algorithm", command=KNN)
knnButton.place(x=700,y=300)
knnButton.config(font=font1)

batButton = Button(main, text="Run DRBA Algorithm with BAT", command=DRBABAT)
batButton.place(x=700,y=350)
batButton.config(font=font1)

nbButton = Button(main, text="Run DRBA Algorithm with PSO", command=DRBAPSO)
nbButton.place(x=700,y=400)
nbButton.config(font=font1)

treeButton = Button(main, text="Accuracy Graph", command=accuracyGraph)
treeButton.place(x=700,y=450)
treeButton.config(font=font1)

lrButton = Button(main, text="Precision Graph", command=precisionGraph)
lrButton.place(x=700,y=500)
lrButton.config(font=font1)


randomButton = Button(main, text="Recall Graph", command=recallGraph)
randomButton.place(x=700,y=550)
randomButton.config(font=font1)

predictButton = Button(main, text="Predict Malware from New File", command=predict)
predictButton.place(x=700,y=600)
predictButton.config(font=font1)



font1 = ('times', 12, 'bold')
text=Text(main,height=30,width=80)
scroll=Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=10,y=100)
text.config(font=font1)


main.config(bg='turquoise')
main.mainloop()
