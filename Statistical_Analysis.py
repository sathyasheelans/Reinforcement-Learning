import re
from textwrap import wrap
import datetime as dt
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers
from scapy.fields import *
import pandas as pd
import codecs
from bs4 import BeautifulSoup as bs
import time
import binascii
import sys
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
from IPython.display import display
import matplotlib.dates as mdates
from matplotlib import cm
from sklearn import preprocessing
from scipy.stats import norm


def normal_dist(x , mean , sd):
    prob_density = (np.pi*sd) * np.exp(-0.5*((x-mean)/sd)**2)
    return prob_density

Xtr_path = 'log1.csv'


data = np.loadtxt(Xtr_path, delimiter=",",dtype=str)
df =pd.DataFrame(data)
df = df.replace(r'^\s*$', np.NaN, regex=True)
#Time =np.array(df[0],dtype=np.float128)

speed=np.array(df[1]).astype(np.float64)

speed=np.delete(speed,0)
print(speed,len(speed),df[0])



# scaler = preprocessing.StandardScaler().fit(speed.reshape(-1, 1))
# speed = scaler.transform(speed.reshape(-1, 1))
#speed = preprocessing.normalize(Xts_pa[~np.isnan(Xts_pa)].reshape(-1, 1), norm='l1')
#speed = preprocessing.normalize(speed[~np.isnan(speed)].reshape(-1, 1), norm='l2')


mean = np.mean(speed[~np.isnan(speed)])
sd = np.std(speed[~np.isnan(speed)])
min=np.min(speed[~np.isnan(speed)])

print(speed[0])
print(mean,sd)

pdf=norm.pdf(speed[~np.isnan(speed)], mean, sd)
#pdf = normal_dist(speed,mean,sd)

# plt.plot(pdf,'o',color = 'red')
# plt.plot(speed,color = 'blue')
# plt.xlabel('Time instances')
# plt.ylabel('Data Rate')
# plt.legend(['Speed in bps'])

# plt.ylim(np.nanmin(speed), np.nanmax(speed))

# plt.show()


fig, ax = plt.subplots()

ax.plot(pdf[:10000],'o', color='red')
ax.tick_params(axis='y', labelcolor='red')

# Generate a new Axes instance, on the twin-X axes (same position)
ax2 = ax.twinx()
ax2.plot(speed[:10000], color='blue')
#ax2.set_yscale('log')
ax2.tick_params(axis='y', labelcolor='blue')
mean_array=[mean]*len(speed)
sd_array=[sd]*len(speed)
ax2.plot(mean_array[:10000], color='green', lw=2, ls='--', label="Mean")
#ax2.plot(sd_array[:1000], color='black', lw=2, ls='--', label="Standard Deviation")

ax.set_xlabel('Frequency 100 Hz')
ax.set_ylabel('PDF of Normal Distribution', color='g')
ax2.set_ylabel('Speed in bps', color='b')

plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)

plot2=plt.figure(2)
plt.hist(speed[:10000],range=[20000000, 215000000])
plt.ylim=[0,100]
#ax.plot(speed[:100000], color='blue')

plt.show()

