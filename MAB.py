import re
from textwrap import wrap
import datetime as dt
import pandas as pd
import time
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
from IPython.display import display
import matplotlib.dates as mdates
from matplotlib import cm
from sklearn import preprocessing
from scipy.stats import norm

global k,T
k = 10
T = 1000

def greedy():
    Qt=np.zeros(k)
    N=0
    for i in k:
