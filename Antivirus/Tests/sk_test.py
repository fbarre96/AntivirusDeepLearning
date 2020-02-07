print(__doc__)

# Author: Gael Varoquaux <gael dot varoquaux at normalesup dot org>
# License: BSD 3 clause

# Standard scientific Python imports
import matplotlib.pyplot as plt

# Import datasets, classifiers and performance metrics
from sklearn import datasets, svm, metrics
import os
import numpy as np
import random
# The virus dataset
values=[]
targets=[]
for i in range(10000):
    contenu = random.randint(0,1)
    values.append(contenu)
    if contenu == 1:
        targets.append("virus")
    else:
        targets.append("clean")

n_samples = 10000
np_values = np.array(values).reshape(-1,1)
np_targets = np.array(targets)
# Create a classifier: a support vector classifier
classifier = svm.SVC(gamma=1)

# We learn the digits on the first half of the digits
classifier.fit(np_values[:n_samples // 2], np_targets[:n_samples // 2])

# Now predict the value of the digit on the second half:
expected = np_targets[n_samples // 2:]
predicted = classifier.predict(np_values[n_samples // 2:])

print("Classification report for classifier %s:\n%s\n"
      % (classifier, metrics.classification_report(expected, predicted)))
print("Confusion matrix:\n%s" % metrics.confusion_matrix(expected, predicted))


plt.show()
