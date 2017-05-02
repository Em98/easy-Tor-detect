# -*- coding: utf-8 -*-
from datetime import datetime
import re

class FingerPrint(object):
    def __init__(self, cipherSuite, validity, caList):
        self.cipherSuite = cipherSuite
        self.validity = validity
        self.caList = caList

    def __str__(self):
        return self.caList

    def _getDuration(self, notBeforStr, notAfterStr):
        notBefor = datetime.strptime(notBeforStr, "%y-%m-%d %H:%M:%S (UTC)")
        notAfter = datetime.strptime(notAfterStr, "%y-%m-%d %H:%M:%S (UTC)")
        return int((notAfter - notBefor).days)


    def _checkCipherSuite(self):
        pass

    def _getCertDuration(self):
        durationList = []
        CACount = len(self.validity)/2
        IndexList = [2 * item for item in range(CACount)]
        print IndexList
        for Index in IndexList:
            notBefor = self.validity[Index]
            notAfter = self.validity[Index + 1]
            durationList.append(self._getDuration(notBefor, notAfter))
        return durationList

    def _checkCACommonName(self):
        for commonName in self.caList:
            if not re.match(r'^www.[a-zA-Z0-9]{8,20}.net$', commonName):
                return False
        return True


    def isTorFingerPrint(self):
        #check CA Common Name
        if not self._checkCACommonName():
            return False
        #Check Certificate Duration
        durationList = self._getCertDuration()
        print durationList
        for duration in durationList:
            if duration > 365:
                return False
        return True



