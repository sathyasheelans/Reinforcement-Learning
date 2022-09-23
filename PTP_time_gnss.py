"""
%% Software License Agreement (Proprietary)
%{
*********************************************************************
 *
 *  Copyright (c) 2022, Motional.
 *  All rights reserved.
 *  Created by:
 *            Sathyasheelan Santhanam, Motional
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution. 
 *   * Neither the name of Motional. nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *  COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 *  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *********************************************************************/
%}

%{
%% Notes

This is a PCAP parser which retrieves the GNSS time, GVPM System time, 
GVPM arrival time, PTP arrival time, PTP time and finds the drift 
betweenn these

%Written (and last modified) by Sathyasheelan Santhanam Aug 15, 2022.
%V2.0  Copyright Motional 2022.
%************************************************************
%}
"""
import re
from textwrap import wrap
import datetime as dt
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers
from scapy.fields import *
import pandas as pd
from bs4 import BeautifulSoup as bs
import time
import binascii
import sys
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
from IPython.display import display
import matplotlib.dates as mdates


# CUstom IEEE1588 layer which will be used to decode the PTP packets
class ieee1588(Packet):
    name = "Precision Time Protocol"
    fields_desc = [
        BitField('transportSpecific', 1, 4),
        BitField('messageType', 0, 4),
        ByteField('versionPTP', 2),
        LenField('messageLength', 0, fmt="H"),
        ByteField('subdomainNumber', 0),
        ByteField('dummy1', 0),
        XShortField('flags', 0),
        LongField('correction', 0),
        IntField('dummy2', 0),
        XLongField('ClockIdentity', 0),
        XShortField('SourcePortId', 0x0002),
        XShortField('sequenceId', 0x0566),
        ByteField('control', 0),
        SignedByteField('logMessagePeriod', 0),
        Field('TimestampSec', 0, fmt='6s'), 
        IntField('TimestampNanoSec', 0)
    ]

bind_layers(Ether, ieee1588, type=0x88F7)

class PCAP2XML():
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.file_name_one = 'GNSS_'+dt.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        #self.file_name_one = 'GNSS1'
        home = os.path.expanduser('~')
        self.path = os.path.join(home, 'TestResults/GNSS')
        #self.path = os.path.join(home, 'Haiyan_Git/componentengineering/Post_Processing')
        if not os.path.isdir(self.path):
            os.mkdir(self.path)
			
    def pcap_to_xml(self):
        """function that converts pcap to xml using scapy"""
        packets = rdpcap(self.pcap_file)
        print(packets)
        with open(os.path.join(self.path, self.file_name_one+'.xml'), 'w') as file:
            for pkt in packets:
                if pkt.getlayer(Raw):
                    list_element = pkt.getlayer(Raw)
                    file.write(str(list_element))


class GNSSXMLPostProcessing():
    """Class for post processing the GNSS XML files.  Constructor takes file path as input."""
    def __init__(self, xml_file):
        """Init method, creates results file from XML file name"""
        self.xml_file = xml_file
        self.result_file = os.path.splitext(xml_file)[0] + ".csv"
        self.header = ['time','second(NAN)','raw_lat', 'raw_long', 'conv_lat', 'conv_long','systime']
        #self.gps_lat_gt = 40.687788
        #self.gps_long_gt = -73.951041

    def parse_lat_long(self):
        """parse the lat/long tags from XML file"""
        global LATS, LONGS, YEA, MON, DAY, HOU, MIN, SEC, NAN, SYT

        content = []
        with open(self.xml_file) as file:
            content = file.readlines()
            content = "".join(content)
            bs_content = bs(content, "lxml")
            LATS = bs_content.find_all("lat")
            LONGS = bs_content.find_all("lon")
            YEA = bs_content.find_all("yea")
            MON = bs_content.find_all("mon")
            DAY = bs_content.find_all("day")
            HOU = bs_content.find_all("hou")
            MIN = bs_content.find_all("min")
            SEC = bs_content.find_all("sec")
            NAN = bs_content.find_all("nan")
            SYT = bs_content.find_all("syt")
            file.close()

    def convert_contents(self):
        """convert the raw tags of lat/long to offsets and save"""
        global CONV_LATS, CONV_LONGS, CONV_TIME, CONV_SYT, CONV_NAN,SYT_Ta,epoch

        
		
        CONV_LATS = []
        CONV_LONGS = []
        CONV_TIME = []
        CONV_SYT = []
        CONV_NAN = []
        CONV_NAN=[]
        SYT_Ta=[]
        epoch=[]
        
        count = 0
        for _ in YEA:
            CONV_TIME.append(str(YEA[count].get_text())+'-'+str(MON[count].get_text())+'-'+str(DAY[count].get_text())+' '+str(HOU[count].get_text())+':'+str(MIN[count].get_text())+':'+str(SEC[count].get_text()))
            count += 1
            
        count = 0            
        for _ in NAN:
            CONV_NAN.append(float(NAN[count].get_text())/1E9)
            count += 1
            
        count = 0
        for _ in LATS:
            CONV_LATS.append(float(LATS[count].get_text()) * 1E-7)
            #DEG_LAT_OFFSETS.append(abs(CONV_LATS[count] - self.gps_lat_gt))
            #METER_LAT_OFFSETS.append(DEG_LAT_OFFSETS[count] * 111139)
            count += 1

        count = 0
        for _ in LONGS:
            CONV_LONGS.append(float(LONGS[count].get_text()) * 1E-7)
            #DEG_LONG_OFFSETS.append(abs(CONV_LONGS[count] - self.gps_long_gt))
            #METER_LONG_OFFSETS.append(DEG_LONG_OFFSETS[count] * 111139)
            count += 1
            
        count = 0
        for _ in SYT:
            CONV_SYT.append(time.strftime('%Y-%m-%d %H:%M:%S.%f', time.localtime(float(SYT[count].get_text()))))
            SYT_Ta.append(float(SYT[count].get_text()))
            count += 1

        df=pd.DataFrame({'CONV_TIME':CONV_TIME,'CONV_NAN':CONV_NAN,'SYT':SYT_Ta})

        return df

def main():

    #read the packets in the pcap file
    packets = rdpcap("test.pcap")

    arr_all=[]
    arr_ptp=[]
    arr_gvpm=[]
    gvpm_sys=[]
    gnss_time=[]
    OrSec=[]
    sys_v=[]

    count =0
    for pkt in packets:

        #getting the arrival time of all packets
        arr_all.append(pkt.time)

        #CHeck for PTPV2 packets
        if pkt[Ether].type==35063:

            #Check for followup messages in PTPV2
            if pkt[ieee1588].control ==2:
                #print(pkt.time)
                #print(pkt.show())

                #Extract the required information
                data= binascii.hexlify(pkt[ieee1588].TimestampSec)
                Origintime_Sec=int(data,16)
                #print(pkt[ieee1588].TimestampNanoSec)
                Origintime_Nanosec=pkt[ieee1588].TimestampNanoSec
                if len(str(Origintime_Nanosec))==8:
                    Origintime_Nanosec='0'+str(Origintime_Nanosec)
                else:
                    Origintime_Nanosec=str(Origintime_Nanosec)

                arr_ptp.append(pkt.time)
                arr_gvpm.append(np.NaN)
                OrSec.append(np.float128(str(Origintime_Sec)+"."+Origintime_Nanosec))
                gvpm_sys.append(np.NaN)
                gnss_time.append(np.NaN)


            else:
                
                #Append NaN
                arr_ptp.append(np.NaN)
                arr_gvpm.append(np.NaN)
                OrSec.append(np.NaN)
                gvpm_sys.append(np.NaN)
                gnss_time.append(np.NaN)


        #Check for UDP packets
        elif pkt[Ether].type==2048:
            #print(pkt[Raw].load)
            if pkt[Ether].proto==17:

                #Extract GNSS time and GVPM system time
                bs_content = bs(str(pkt[Raw].load), "lxml")
                SYT = str(bs_content.find_all("syt"))
                # regex to extract required strings
                tag = "syt"
                reg_str = "<" + tag + ">(.*?)</" + tag + ">"
                sys_time = re.findall(reg_str, SYT)
                #print(res)
                #print(LATS)
                gvpm_sys.append(np.float128(sys_time[0]))

                YEA = str(bs_content.find_all("yea"))
                MON = str(bs_content.find_all("mon"))
                DAY = str(bs_content.find_all("day"))
                HOU = str(bs_content.find_all("hou"))
                MIN = str(bs_content.find_all("min"))
                SEC = str(bs_content.find_all("sec"))
                NAN = str(bs_content.find_all("nan"))

                # regex to extract required strings
                tag_list = {"yea":YEA,"mon":MON,"day":DAY,"hou":HOU,"min":MIN,"sec":SEC,"nan":NAN}
                
                for html_tag, value in tag_list.items():
 
                    tag = html_tag
                    reg_str = "<" + tag + ">(.*?)</" + tag + ">"
                    sys_v.append(re.findall(reg_str, value)[0])
                    #print(re.findall(reg_str, value)[0])
                

                if len(sys_v[6])==5:
                    sys_v[6]='0000'+sys_v[6]
                
                #print(res)
                #print(LATS)
                gnss_time.append(sys_v[0]+'-'+sys_v[1]+'-'+sys_v[2]+' '+sys_v[3]+':'+sys_v[4]+':'+sys_v[5]+'.'+sys_v[6])
                sys_v.clear()
                arr_ptp.append(np.NaN)
                arr_gvpm.append(pkt.time)
                OrSec.append(np.NaN)
            else:

                arr_ptp.append(np.NaN)
                arr_gvpm.append(np.NaN)
                OrSec.append(np.NaN)
                gvpm_sys.append(np.NaN)
                gnss_time.append(np.NaN)               


        else:
            arr_ptp.append(np.NaN)
            arr_gvpm.append(np.NaN)
            OrSec.append(np.NaN)
            gvpm_sys.append(np.NaN)
            gnss_time.append(np.NaN)

        count=count +1
 
    #Create a panda dataframe with all the required time
    df=pd.DataFrame({'Arrival_all':arr_all,'PTP_Arrival_time':arr_ptp,'GVPM_Arrival_time':arr_gvpm,'PrecisionOrigintime_Sec':OrSec,'GVPM_SYS':gvpm_sys})
    df=df.mul(1000000000)
    Arrivaltime_All =np.array(df['Arrival_all'],dtype=np.float128).astype('datetime64[ns]')
    Arrivaltime_gvpm =np.array(df['GVPM_Arrival_time'],dtype=np.float128).astype('datetime64[ns]')
    Arrivaltime_ptp = np.array(df['PTP_Arrival_time'],dtype=np.float128).astype('datetime64[ns]')
    POrigintime_Sec = np.array(df['PrecisionOrigintime_Sec'],dtype=np.float128).astype('datetime64[ns]')
    GVPM_SYS_TIME=np.array(df['GVPM_SYS'],dtype=np.float128).astype('datetime64[ns]')
    a=np.array(gnss_time)
    GNSS_TIME=pd.to_datetime(a)

    #Calcute error in GVPM arrival time and GNSS Time
    error_gvpmarr_gnss=Arrivaltime_gvpm-GNSS_TIME

    #Calculate error in GVPM arrival time and GVPM system time
    error_gvpmarr_gvpmsys=Arrivaltime_gvpm-GVPM_SYS_TIME

    #Calculate error in PTP arrival time and PTP time
    error_gptp_arr_prec=Arrivaltime_ptp-POrigintime_Sec

    #Calculate error in GVPM system time and GNSS time
    error_gvpmsys_gnss=GVPM_SYS_TIME-GNSS_TIME

    mean = np.mean(error_gptp_arr_prec[~np.isnan(error_gptp_arr_prec)])
    mean_array=[mean]*len(error_gptp_arr_prec)
    print(str(mean))
    
    myFmt = mdates.DateFormatter("%M:%S")

    #Plots

    #plt.gca().xaxis.set_major_locator(mdates.HourLocator(interval=100))
    # plt.gcf().autofmt_xdate()
    """
    plt.figure("Time plots")
    plt.suptitle("Time plots")
    plt.tight_layout()
    plt.subplot(2, 2, 1)
    plt.title("PTP Timestamp vs GVPM System Time")
    a=plt.scatter(Arrivaltime_All[-100:],POrigintime_Sec[-100:],s=0.5,color='b')
    b=plt.scatter(Arrivaltime_All[-100:],GVPM_SYS_TIME[-100:],s=0.5,color='r')
    plt.legend((a,b),('PTP Timestamp','GVPM System Time'), loc='upper left')
    plt.xticks(rotation=30)       # rotate the xticklabels by 30 deg
    plt.gca().xaxis.set_major_formatter(myFmt)
    #plt.xlabel("Arrival Time of All Packets")
    plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)

    #plt.figure("PTP Timestamp vs GNSS Time")
    plt.subplot(2, 2, 2)
    plt.title("PTP Timestamp vs GNSS Time")
    c=plt.scatter(Arrivaltime_All[-100:],POrigintime_Sec[-100:],s=0.5,color='b')
    d=plt.scatter(Arrivaltime_All[-100:],GNSS_TIME[-100:],s=0.5,color='r')
    plt.legend((c,d),('PTP TImestamp','GNSS time'), loc='upper left')
    plt.xticks(rotation=30)       # rotate the xticklabels by 30 deg
    plt.gca().xaxis.set_major_formatter(myFmt)
    #plt.xlabel("Arrival Time of All Packets")
    plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)

    #plt.figure("PTP Timestamp vs GVPM Arrival time")
    plt.subplot(2, 2, 3)
    plt.title("PTP Timestamp vs GVPM Arrival time")
    e=plt.scatter(Arrivaltime_All[-100:],POrigintime_Sec[-100:],s=0.5,color='b')
    f=plt.scatter(Arrivaltime_All[-100:],Arrivaltime_gvpm[-100:],s=0.5,color='r')
    plt.legend((e,f),('PTP Timestamp','GVPM arrival time'), loc='upper left')
    plt.xticks(rotation=30)       # rotate the xticklabels by 30 deg
    plt.gca().xaxis.set_major_formatter(myFmt)
    plt.xlabel("Arrival Time of All Packets")
    plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)

    #plt.figure("GVPM Arrival time vs GVPM System time")
    plt.subplot(2, 2, 4)
    plt.title("GVPM Arrival time vs GVPM System time")
    g=plt.scatter(Arrivaltime_All[-100:],POrigintime_Sec[-100:],s=0.5,color='b')
    h=plt.scatter(Arrivaltime_All[-100:],Arrivaltime_gvpm[-100:],s=0.5,color='r')
    plt.legend((g,h),('GVPM Arrival time','GVPM System time'), loc='upper left')
    plt.xticks(rotation=30)       # rotate the xticklabels by 30 deg
    plt.gca().xaxis.set_major_formatter(myFmt)
    plt.xlabel("Arrival Time of All Packets")
    plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)

    plt.figure("GVPM System time vs GVPM Arrival time vs PTP Timestamp")
    plt.title("GVPM System time vs GVPM Arrival time vs PTP Timestamp")
    i=plt.scatter(Arrivaltime_All,GVPM_SYS_TIME,s=0.5,color='b')
    j=plt.scatter(Arrivaltime_All,Arrivaltime_gvpm,s=0.5,color='r')
    k=plt.scatter(Arrivaltime_All,POrigintime_Sec,s=0.5,color='g')
    plt.legend((i,j,k),('GVPM System time','GVPM Arrival time','PTP Timestamp'), loc='upper left')
    plt.xticks(rotation=30)       # rotate the xticklabels by 30 deg
    plt.gca().xaxis.set_major_formatter(myFmt)
    plt.xlabel("Arrival Time of All Packets")
    plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)
    """

    plt.figure("Time plots")
    plt.suptitle("Time plots last 50 data packets")
    plt.tight_layout()
    plt.subplot(2, 2, 1)
    plt.title("PTP Timestamp vs GVPM System Time")
    a=plt.scatter(Arrivaltime_All[-50:],POrigintime_Sec[-50:],color='b')
    b=plt.scatter(Arrivaltime_All[-50:],GVPM_SYS_TIME[-50:],color='r')
    plt.legend((a,b),('PTP Timestamp','GVPM System Time'), loc='upper left')
    plt.xticks(rotation=30)       # rotate the xticklabels by 30 deg
    plt.gca().xaxis.set_major_formatter(myFmt)
    #plt.xlabel("Arrival Time of All Packets")
    plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)

    #plt.figure("PTP Timestamp vs GNSS Time")
    plt.subplot(2, 2, 2)
    plt.title("PTP Timestamp vs GNSS Time")
    c=plt.scatter(Arrivaltime_All[-50:],POrigintime_Sec[-50:],color='b')
    d=plt.scatter(Arrivaltime_All[-50:],GNSS_TIME[-50:],color='r')
    plt.legend((c,d),('PTP TImestamp','GNSS time'), loc='upper left')
    plt.xticks(rotation=30)       # rotate the xticklabels by 30 deg
    plt.gca().xaxis.set_major_formatter(myFmt)
    #plt.xlabel("Arrival Time of All Packets")
    plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)

    #plt.figure("PTP Timestamp vs GVPM Arrival time")
    plt.subplot(2, 2, 3)
    plt.title("GNSS Time vs GVPM System time")
    e=plt.scatter(Arrivaltime_All[-50:],GNSS_TIME[-50:],color='b')
    f=plt.scatter(Arrivaltime_All[-50:],GVPM_SYS_TIME[-50:],color='r')
    plt.legend((e,f),('PTP Timestamp','GVPM arrival time'), loc='upper left')
    plt.xticks(rotation=30)       # rotate the xticklabels by 30 deg
    plt.gca().xaxis.set_major_formatter(myFmt)
    plt.xlabel("Arrival Time of All Packets")
    plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)

    #plt.figure("GVPM Arrival time vs GVPM System time")
    plt.subplot(2, 2, 4)
    plt.title("GVPM Arrival time vs GVPM System time")
    g=plt.scatter(Arrivaltime_All[-50:],POrigintime_Sec[-50:],color='b')
    h=plt.scatter(Arrivaltime_All[-50:],Arrivaltime_gvpm[-50:],color='r')
    plt.legend((g,h),('GVPM Arrival time','GVPM System time'), loc='upper left')
    plt.xticks(rotation=30)       # rotate the xticklabels by 30 deg
    plt.gca().xaxis.set_major_formatter(myFmt)
    plt.xlabel("Arrival Time of All Packets")
    plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)

    plt.figure("Error Plots")
    plt.suptitle("Error plots")
    plt.subplot(2, 2, 1)
    plt.title("Error in GVPM Arrival time vs GNSS Time")
    plt.scatter(range(0,len(error_gvpmarr_gnss)),error_gvpmarr_gnss)
    plt.ylabel("error in Nano seconds")
    plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)

    #plt.figure("Error in GVPM Arrival time vs GVPM System time")
    plt.subplot(2, 2, 2)
    plt.title("Error in GVPM Arrival time vs GVPM System time")
    plt.scatter(range(0,len(error_gvpmarr_gvpmsys)),error_gvpmarr_gvpmsys)
    plt.ylabel("error in Nano seconds")
    plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)

    #plt.figure("Error in GVPM System time vs GNSS Time")
    plt.subplot(2, 2, 3)
    plt.title("Error in GVPM System time vs GNSS Time")
    plt.scatter(range(0,len(error_gvpmsys_gnss)),error_gvpmsys_gnss)
    plt.ylabel("error in Nano seconds")
    plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)

    #plt.figure("Error in PTP Arrival time vs PTP Timestamp")
    plt.subplot(2, 2, 4)
    plt.title("Error in PTP Arrival time vs PTP Timestamp")
    plt.scatter(range(0,len(error_gptp_arr_prec)),error_gptp_arr_prec)
    plt.ylabel("error in Nano seconds")
    plt.grid(color = 'green', linestyle = '--', linewidth = 0.5)
    plt.plot(mean_array, color='red', lw=1, ls='--', label="Mean")
    plt.show()

if __name__ == '__main__':
    main()