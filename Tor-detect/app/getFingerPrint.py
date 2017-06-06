# -*- coding: utf-8 -*-

import pyshark
import re
import fingerPrint
import subprocess
import os
from app import UPLOAD_FOLDER, CATCH_FOLDER

def getFingerPrint(layerList):
    fingerPrintDict = {}
    if len(layerList) == 2: #serverhello and certificate are not in the same packet
        serverHello = layerList[0]
        certificate = layerList[1]
        cipherSuite = serverHello.get_field_list_by_showname('Cipher Suite')
        validity = certificate.get_field_list_by_showname('utcTime')
        CACount = len(validity) / 2
        CA = certificate.get_field_by_showname('RDNSequence item').all_fields
        caList = []
        for item in CA:
            m = re.match(r"^1 item \(id-at-commonName=(.*)\)", item.showname_value )
            if m:
                caList.append(m.group(1))
        caList = caList[1::2]

    else:                   #serverhello and certificate are in the same packet
        sslLayer = layerList[0]
        cipherSuite = sslLayer.get_field_by_showname("Cipher Suite").all_fields[0].showname_value
        cipherSuite = cipherSuite.split(' ')[0]
        validity = sslLayer.get_field_list_by_showname('utcTime')
        CACount = len(validity) / 2
        CA = sslLayer.get_field_by_showname('RDNSequence item').all_fields
        caList = []
        for item in CA:
            m = re.match(r"^1 item \(id-at-commonName=(.*)\)", item.showname_value)
            if m:
                caList.append(m.group(1))
        caList = caList[1::2]
    for (k, v ) in fingerPrintDict.items():
        print k, ':', v

    return fingerPrint.FingerPrint(cipherSuite, validity, caList)


def isTorExists(name, uuName):
    pcapPath = os.path.join(UPLOAD_FOLDER, uuName)
    outputFileName = ''
    cap = pyshark.FileCapture(pcapPath, display_filter= 'ssl')
    layerList = []
    TorIPList = []
    find = False
    for pkt in cap:
        sslLayer = pkt.ssl
        typeList = sslLayer.get_field_list_by_showname("Content Type")
        if '22' in typeList:    #if this pkt is handshake message
            hsList =  sslLayer.get_field_list_by_showname("Handshake Type")
            if '2' in hsList and '11' in hsList:
                layerList.append(sslLayer)
                newFingerPrint = getFingerPrint(layerList)
                layerList = []
                if newFingerPrint.isTorFingerPrint():
                    find = True
            elif '2' in hsList and '11' not in hsList:
                layerList.append(sslLayer)
                continue
            elif '11' in hsList and '2' not in hsList:
                layerList.append(sslLayer)
                newFingerPrint = getFingerPrint(layerList)
                layerList = []
                if newFingerPrint.isTorFingerPrint():
                    print 'yes'
                    find = True
    if find:
        TorIP = pkt.ip.src
        TorIPList.append(TorIP)
        display = 'ip.src=='+TorIPList[0]+' or ip.dst=='+TorIPList[0]
        if len(TorIPList) > 1:
            for ip in TorIPList[1:]:
                display += ' or ip.src=='+ip+' or ip.dst=='+ip
        afterName = name+'_after_Tor.'+uuName.split('.')[-1]
        outputFileName = os.path.join(CATCH_FOLDER, afterName)
        command = 'tshark -r '+pcapPath+' -Y \"'+display+'\" -w '+outputFileName
        subprocess.Popen(command, shell=True)
        find = False
    return afterName

