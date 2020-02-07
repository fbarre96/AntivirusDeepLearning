# https://www.tensorflow.org/tutorials/keras/basic_classification

# TensorFlow and tf.keras
import tensorflow as tf
from tensorflow import keras

# Helper libraries
import numpy as np
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt

fashion_mnist = keras.datasets.fashion_mnist

(train_images, train_labels), (test_images, test_labels) = fashion_mnist.load_data()
# train_images.shape renvoie (60000, 28, 28) donc on a 60000 images de 28 pxl*28pxl. pareil  pour test_images.shape
# len(train_labels) renvoie 60000
# train labels sont des entiers uint8 dans un array
class_names = ['T-shirt/top', 'Trouser', 'Pullover', 'Dress', 'Coat', 
               'Sandal', 'Shirt', 'Sneaker', 'Bag', 'Ankle boot']

# TEST vizualize images,
plt.figure()
plt.imshow(train_images[0])
plt.colorbar()
plt.grid(False)
plt.show()
#  entre 0, 255 pour chaque pixel. On va ramener a un double entre 0 et 1
train_images = train_images / 255.0

test_images = test_images / 255.0

plt.figure(figsize=(10,10))
for i in range(25):
    plt.subplot(5,5,i+1)
    plt.xticks([])
    plt.yticks([])
    plt.grid(False)
    plt.imshow(train_images[i], cmap=plt.cm.binary)
    plt.xlabel(class_names[train_labels[i]])
plt.show()

# Model options
model = keras.Sequential([
    keras.layers.Flatten(input_shape=(28, 28)), # The first layer in this network, tf.keras.layers.Flatten, transforms the format of the images from a 2d-array (of 28 by 28 pixels), to a 1d-array of 28 * 28 = 784 pixels.
    keras.layers.Dense(128, activation=tf.nn.relu), # Dense layer = fully connected nodes. 128 nodes for this
    keras.layers.Dense(10, activation=tf.nn.softmax) # 10 softmax pour les 10 sorties possibles. Softmax = probabilité au dela de laquelle l'image est" reconnue"
])

# Compiler le model (et options)
model.compile(optimizer=tf.train.AdamOptimizer(), # This is how the model is updated based on the data it sees and its loss function.
              loss='sparse_categorical_crossentropy', # This measures how accurate the model is during training. We want to minimize this function to "steer" the model in the right direction.
              metrics=['accuracy']) # Used to monitor the training and testing steps. The following example uses accuracy, the fraction of the images that are correctly classified.

# Entraînement : 

model.fit(train_images, train_labels, epochs=5) # epoches sont des itérations ?

# Estime la précision avec les données de test:
test_loss, test_acc = model.evaluate(test_images, test_labels)

print('Test accuracy:', test_acc)

# Tenter la classification / prediction

predictions = model.predict(test_images)

print(predictions[0]) # on affiche les predictions pour l'image de test à l'index 0. Une prediction est un tableau des 10 resultats de notre softmax layer.
print(np.argmax(predictions[0]))   # en prenant la valeur maximale on a notre classificaiton