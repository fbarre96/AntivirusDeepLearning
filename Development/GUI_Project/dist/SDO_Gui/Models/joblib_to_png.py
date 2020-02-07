from sklearn.externals import joblib
import sys
import pydot
from sklearn.tree import export_graphviz
import numpy as np

if len(sys.argv) != 3:
    print("Usage : python3 joblib_to_png.py <model.joblib> <out_name>")
    sys.exit(0)
classifier = joblib.load(sys.argv[1])
print("Only the first decision tree of the random forest will be extracted.")
estimator = classifier.estimators_[0]

# Export as dot file
export_graphviz(estimator, 
                out_file=sys.argv[2]+'.dot', 
                rounded = True, proportion = False, 
                precision = 2, filled = True)

(graph,) = pydot.graph_from_dot_file(sys.argv[2]+'.dot')
graph.write_png(sys.argv[2]+'.png')