########################################################################################################################
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
########################################################################################################################
import argparse                     # used for parsing command line args
from enum import Enum               # used for creating Service class
import os
import select
from socket import *
from statistics import stdev        # used for computing RTT standard deviation
import struct
import time


########################################################################################################################
# Constants                                                                                                            #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
########################################################################################################################
########################################################################################################################
# ICMP Types                                                                                                           #
#                                                                                                                      #
# References:                                                                                                          #
# http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                                #
# http://sites.uclouvain.be/SystInfo/usr/include/netinet/ip_icmp.h.html                                                #
########################################################################################################################
ICMP_ECHOREPLY       = 0    # Echo Reply
ICMP_DEST_UNREACH    = 3    # Destination Unreachable
ICMP_REDIRECT        = 5    # Redirect (change route)
ICMP_ECHO            = 8    # Echo Request
ICMP_TIME_EXCEEDED   = 11   # Time Exceeded
ICMP_PARAMETERPROB   = 12   # Parameter Problem

########################################################################################################################
# ICMP Codes                                                                                                           #
#                                                                                                                      #
# References:                                                                                                          #
# http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                                #
# http://sites.uclouvain.be/SystInfo/usr/include/netinet/ip_icmp.h.html                                                #
########################################################################################################################
# Codes for UNREACH
ICMP_NET_UNREACH     = 0    # Network Unreachable
ICMP_HOST_UNREACH    = 1    # Host Unreachable
ICMP_PROT_UNREACH    = 2    # Protocol Unreachable
ICMP_PORT_UNREACH    = 3    # Port Unreachable
ICMP_FRAG_NEEDED     = 4    # Fragmentation Needed/DF set
ICMP_SR_FAILED       = 5    # Source Route failed
ICMP_NET_UNKNOWN     = 6    # Destination Network Unknown
ICMP_HOST_UNKNOWN    = 7    # Destination Host Unknown
ICMP_HOST_ISOLATED   = 8    # Source Host Isolated
ICMP_NET_ANO         = 9    # Communication with Destination Network Administratively Prohibited
ICMP_HOST_ANO        = 10   # Communication with Destination Host Administratively Prohibited
ICMP_NET_UNR_TOS     = 11   # Destination Network Unreachable for Type of Service
ICMP_HOST_UNR_TOS    = 12   # Destination Host Unreachable for Type of Service
ICMP_PKT_FILTERED    = 13   # Communication Administratively Prohibited (packet filtered)
ICMP_PREC_VIOLATION  = 14   # Host Precedence violation
ICMP_PREC_CUTOFF     = 15   # Precedence cutoff in effect

# Codes for REDIRECT
ICMP_REDIR_NET       = 0    # Redirect Datagram for the Network (or subnet)
ICMP_REDIR_HOST      = 1    # Redirect Datagram for the Host
ICMP_REDIR_NETTOS    = 2    # Redirect Datagram for TOS and Network
ICMP_REDIR_HOSTTOS   = 3    # Redirect Datagram for TOS and Host

# Codes for TIME_EXCEEDED
ICMP_EXC_TTL         = 0    # TTL Exceeded in Transit
ICMP_EXC_FRAGTIME    = 1    # Fragment Reassembly Time Exceeded

# Codes for PARAMETERPROB 
ICMP_PARAM_PTR       = 0    # Pointer indicates the error
ICMP_PARAM_MRO       = 1    # Missing a Required Option
ICMP_PARAM_BADLEN    = 2    # Bad Length


########################################################################################################################
# Class Service                                                                                                        #
#                                                                                                                      #
# Enum class to store available services that program can use                                                          #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
########################################################################################################################
class Service(Enum):
    PING       = 0
    TRACEROUTE = 1


########################################################################################################################
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
########################################################################################################################
class IcmpHelperLibrary:
    ####################################################################################################################
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    ####################################################################################################################
    class IcmpPacket:
        ################################################################################################################
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        ################################################################################################################
        __icmpTarget: str = ""                        # Remote Host
        __destinationIpAddress: str = ""              # Remote Host IP Address
        __header: bytes = b''                         # Header after byte packing
        __data: bytes = b''                           # Data after encoding
        __dataRaw: str = ""                           # Raw string data before encoding
        __icmpType: int = 0                           # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode: int = 0                           # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum: int = 0                     # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier: int = 0                   # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber: int = 0               # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout: int = 30
        __ttl: int = 255                              # Time to live
        __icmpReplyPacket = None                      # ICMP reply packet
        __service = Service(Service.PING)             # Service this packet class will offer (default to PING)
        __rcvTime: float = 0.0                        # Reply message receive time
        __rcvAddr: tuple = ('', '')                   # Reply message address

        __DEBUG_IcmpPacket: bool = False              # Allows for debug output

        ################################################################################################################
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        ################################################################################################################
        def getIcmpTarget(self) -> str:
            return self.__icmpTarget

        def getDestinationIpAddress(self) -> str:
            return self.__destinationIpAddress

        def getDataRaw(self) -> str:
            return self.__dataRaw

        def getIcmpType(self) -> int:
            return self.__icmpType

        def getIcmpCode(self) -> int:
            return self.__icmpCode

        def getPacketChecksum(self) -> int:
            return self.__packetChecksum

        def getPacketIdentifier(self) -> int:
            return self.__packetIdentifier

        def getPacketSequenceNumber(self) -> int:
            return self.__packetSequenceNumber

        def getTtl(self) -> int:
            return self.__ttl

        def getIcmpReplyPacket(self):
            return self.__icmpReplyPacket

        def getRcvTime(self) -> float:
            return self.__rcvTime

        def getRcvAddr(self) -> tuple:
            return self.__rcvAddr

        ################################################################################################################
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        ################################################################################################################
        def setIcmpTarget(self, icmpTarget: str) -> None:
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType: int) -> None:
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode: int) -> None:
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum: int) -> None:
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier: int) -> None:
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber: int) -> None:
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl: int) -> None:
            self.__ttl = ttl

        def setIcmpReplyPacket(self, reply) -> None:
            self.__icmpReplyPacket = reply

        def setService(self, service) -> None:
            self.__service = service

        def setRcvTime(self, t: float) -> None:
            self.__rcvTime = t

        def setRcvAddr(self, addr: tuple) -> None:
            self.__rcvAddr = addr

        ################################################################################################################
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        ################################################################################################################
        def __recalculateChecksum(self) -> None:
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData: bytes = b''.join([self.__header, self.__data])
            checksum: int = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo: int = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count: int = 0
            while count < countTo:
                thisVal: int = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer: int = ~checksum             # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self) -> None:
            """
            The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            Type = 8 bits
            Code = 8 bits
            ICMP Header Checksum = 16 bits
            Identifier = 16 bits
            Sequence Number = 16 bits
            """

            self.__header = struct.pack("!BBHHH",
                                        self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                        self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                        self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                        self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                        self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                        )

        def __encodeData(self) -> None:
            data_time: bytes = struct.pack("d", time.time())             # Used to track overall round trip time
                                                                         # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded: bytes = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self) -> None:
            """Checksum is calculated with the following sequence to confirm data is up to date"""

            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket) -> None:
            # Track error messages
            err: str = ''

            # ICMP Echo Reply should have Code = 0
            expCode: int = 0 

            # ICMP Echo Reply should have matching timestamp
            # Source: http://www.networksorcery.com/enp/protocol/icmp/msg0.htm
            expTimestamp: float = struct.unpack("d", self.__data[:8])[0]

            # Check if ICMP Echo Request Type = 0
            if icmpReplyPacket.getIcmpType() == ICMP_ECHOREPLY:
                icmpReplyPacket.setIsValidIcmpType(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)
                err += "ERROR: Invalid Type\n"
                err += f"\tExpected: {ICMP_ECHOREPLY}\n"
                err += f"\tActual:   {icmpReplyPacket.getIcmpType()}\n\n"

            # Check if ICMP Echo Request Code = 0
            if icmpReplyPacket.getIcmpCode() == expCode:
                icmpReplyPacket.setIsValidIcmpCode(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)
                err += "ERROR: Invalid Code\n"
                err += f"\tExpected: {expCode}\n"
                err += f"\tActual:   {icmpReplyPacket.getIcmpCode()}\n\n"

            # Check if ICMP Echo Request ID = ICMP Echo Reply ID
            if self.getPacketIdentifier() == icmpReplyPacket.getIcmpIdentifier():
                icmpReplyPacket.setIsValidIcmpIdentifier(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)
                err += "ERROR: Invalid ID\n"
                err += f"\tExpected: {self.getPacketIdentifier()}\n"
                err += f"\tActual:   {icmpReplyPacket.getIcmpIdentifier()}\n\n"

            # Check if ICMP Echo Request Sequence Number = ICMP Echo Reply Sequence Number
            if self.getPacketSequenceNumber() == icmpReplyPacket.getIcmpSequenceNumber():
                icmpReplyPacket.setIsValidIcmpSequenceNumber(True)
                icmpReplyPacket.setIsValidResponse(False)
            else:
                icmpReplyPacket.setIsValidResponse(False)
                err += "ERROR: Invalid Sequence Number\n"
                err += f"\tExpected: {self.getPacketSequenceNumber()}\n"
                err += f"\tActual:   {icmpReplyPacket.getIcmpSequenceNumber()}\n\n"

            # Check if ICMP Echo Request Data = ICMP Echo Reply Data (timestamp only)
            if expTimestamp == icmpReplyPacket.getDateTimeSent():
                icmpReplyPacket.setIsValidDateTimeSent(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)
                err += "ERROR: Invalid Timestamp\n"
                err += f"\tExpected: {expTimestamp}\n"
                err += f"\tActual:   {icmpReplyPacket.getDateTimeSent()}\n"

            # Check if ICMP Echo Request Data = ICMP Echo Reply Data (excluding timestamp)
            if self.getDataRaw() == icmpReplyPacket.getIcmpData():
                icmpReplyPacket.setIsValidIcmpData(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)
                err += "ERROR: Invalid Data\n"
                err += f"\tExpected: {self.getDataRaw()}\n"
                err += f"\tActual:   {icmpReplyPacket.getIcmpData()}\n"

            # Store error message for later retrieval
            icmpReplyPacket.setErrMsg(err)

            # Set isValidResponse flag to True if all 3 fields valid
            if icmpReplyPacket.isValidIcmpIdentifier() and \
                    icmpReplyPacket.isValidIcmpSequenceNumber() and \
                    icmpReplyPacket.isValidDateTimeSent() and \
                    icmpReplyPacket.isValidIcmpData():
                icmpReplyPacket.setIsValidResponse(True)

        ################################################################################################################
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        ################################################################################################################
        def buildPacket_echoRequest(self, packetIdentifier: int, packetSequenceNumber: int) -> None:
            self.setIcmpType(ICMP_ECHO)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            if self.__service == Service.PING:
                print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    if self.__service == Service.PING:
                        print("  *        *        *        *        *    Request timed out.")

                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                                                            # addr  - address of socket sending data
                timeReceived = time.time()
                if self.__service == Service.TRACEROUTE:
                    self.setRcvTime(timeReceived)
                    self.setRcvAddr(addr)

                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    if self.__service == Service.PING:
                        print("  *        *        *        *        *    Request timed out (By no remaining time left).")
                else:
                    # Extract ICMP Reply Packet
                    self.setIcmpReplyPacket(IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket))

                    # Validate ICMP Reply Checksum
                    self.getIcmpReplyPacket().validateChecksum()

                    # Proceed to inspect Type and Code only if Checksum is Valid
                    # Reference: TCP/IP Illustrated Volume 1, 2nd Ed., by Kevin R. Fall and W. Richard Stevens
                    #     Section 8.1: If an ICMP implementation receives an ICMP message with a bad checksum, the
                    #                  message is discarded.
                    if self.getIcmpReplyPacket().isValidChecksum():
                        # NOTE: Given this program's main purpose is to make ICMP echo requests, certain ICMP response
                        # types can be ignored. The main types that this program will handle include:
                        #     1. Echo Reply
                        #     2. Destination Unreachable
                        #     3. Redirect
                        #     4. Time Exceeded 
                        #     5. Parameter Problem
                        # Any type that is not handled will display an "Unhandled Type" message.  
                        # Reference: https://github.com/torvalds/linux/blob/master/net/ipv4/ping.c

                        # Fetch the ICMP type and code from the received packet
                        icmpType, icmpCode = recvPacket[20:22]

                        # Store debug msg for later display
                        debugMsg: str = ''

                        # Type 0: Echo Reply
                        if icmpType == ICMP_ECHOREPLY:
                            debugMsg += "[Echo Reply]"

                            if self.__service == Service.PING:
                                # Code 0: Default 
                                if icmpCode == 0:
                                   self.__validateIcmpReplyPacketWithOriginalPingData(self.getIcmpReplyPacket())
                                   self.getIcmpReplyPacket().printResultToConsole(self.getTtl(), timeReceived, addr)

                                # Generate detailed debug message
                                if self.__DEBUG_IcmpPacket:
                                   self.generateDetailedDebugMsg()

                                # Echo reply is the end and therefore should return
                                return

                        # Handle other Types 
                        else:
                            if self.__service == Service.PING:
                                # Add message stats to debug
                                # Format (ex): TTL=255   RTT=100 ms  Type=3   Code=0   172.0.0.1   [Network Unreachable]
                                debugMsg += f"  TTL={self.getTtl()}    RTT={(timeReceived - pingStartTime) * 1000:.0f} ms"
                                debugMsg += f"    Type={icmpType}    Code={icmpCode}    {addr[0]}    " 

                            # Type 3: Destination Unreachable
                            if icmpType == ICMP_DEST_UNREACH:
                                # NOTE
                                # Reference: TCP/IP Illustrated Volume 1 2nd Ed. by Kevin R. Fall and W. Richard Stevens
                                # Section 8.3.2: Although 16 different codes are defined for this message in ICMPv4, 
                                #                only 4 are commonly used. These include:
                                #                    1. Host Unreachable (code 1), 
                                #                    2. Port Unreachable (code 3), 
                                #                    3. Fragmentation Required/Don't-Fragment Specified (code 4), and 
                                #                    4. Communication Administratively Prohibited (code 13).

                                # Code 0: Network Unreachable
                                if icmpCode == ICMP_NET_UNREACH:
                                    debugMsg += "[Network Unreachable]"

                                # Code 1: Host Unreachable
                                elif icmpCode == ICMP_HOST_UNREACH:
                                    debugMsg += "[Host Unreachable]"

                                # Code 2: Protocol Unreachable
                                elif icmpCode == ICMP_PROT_UNREACH:
                                    debugMsg += "[Protocol Unreachable]"

                                # Code 3: Port Unreachable
                                elif icmpCode == ICMP_PORT_UNREACH:
                                    debugMsg += "[Port Unreachable]"

                                # Code 4: Fragmentation Needed/DF Set
                                elif icmpCode == ICMP_FRAG_NEEDED:
                                    debugMsg += "[Fragmentation Needed/DF Set]"

                                # Code 5: Source Route failed
                                elif icmpCode == ICMP_SR_FAILED:
                                    debugMsg += "[Source Route failed]"

                                # Code 6: Destination Network Unknown
                                elif icmpCode == ICMP_NET_UNKNOWN:
                                    debugMsg += "[Destination Network Unknown]"

                                # Code 7: Destination Host Unknown
                                elif icmpCode == ICMP_HOST_UNKNOWN:
                                    debugMsg += "[Destination Host Unknown]"

                                # Code 8: Source Host Isolated
                                elif icmpCode == ICMP_HOST_ISOLATED:
                                    debugMsg += "[Source Host Isolated]"

                                # Code 9: Communication with Destination Network Administratively Prohibited
                                elif icmpCode == ICMP_NET_ANO:
                                    debugMsg += "[Communication with Destination Network Administratively Prohibited]"

                                # Code 10: Communication with Destination Host Administratively Prohibited
                                elif icmpCode == ICMP_HOST_ANO:
                                    debugMsg += "[Communication with Destination Host Administratively Prohibited]"

                                # Code 11: Destination Network Unreachable for Type of Service
                                elif icmpCode == ICMP_NET_UNR_TOS:
                                    debugMsg += "[Destination Network Unreachable for TOS]"

                                # Code 12: Destination Host Unreachable for Type of Service
                                elif icmpCode == ICMP_HOST_UNR_TOS:
                                    debugMsg += "[Destination Host Unreachable for TOS]"

                                # Code 13: Communication Administratively Prohibited (packet filtered)
                                elif icmpCode == ICMP_PKT_FILTERED:
                                    debugMsg += "[Communication Administratively Prohibited]"

                                # Code 14: Host Precedence violation
                                elif icmpCode == ICMP_PREC_VIOLATION:
                                    debugMsg += "[Host Precedence violation]"

                                # Code 15: Precedence cutoff in effect
                                elif icmpCode == ICMP_PREC_CUTOFF:
                                    debugMsg += "[Precedence cutoff in effect]"

                            # Type 5: Redirect
                            elif icmpType == ICMP_REDIRECT:

                                # Code 0: Redirect Datagram for the Network (or subnet)
                                if icmpCode == ICMP_REDIR_NET:
                                    debugMsg += "[Redirect Datagram for Network]"

                                # Code 1: Redirect Datagram for the Host
                                elif icmpCode == ICMP_REDIR_HOST:
                                    debugMsg += "[Redirect Datagram for Host]"

                                # Code 2: Redirect Datagram for TOS and Network
                                elif icmpCode == ICMP_REDIR_NETTOS:
                                    debugMsg += "[Redirect Datagram TOS and Network]"

                                # Code 3: Redirect Datagram for TOS and Host
                                elif icmpCode == ICMP_REDIR_HOSTTOS:
                                    debugMsg += "[Redirect Datagram TOS and Host]"

                            # Type 11: Time Exceeded
                            elif icmpType == ICMP_TIME_EXCEEDED:

                                # Code 0: TTL Exceeded in Transit
                                if icmpCode == ICMP_EXC_TTL:
                                    debugMsg += "[TTL Exceeded in Transit]"

                                # Code 1: Fragment Reassembly Time Exceeded
                                elif icmpCode == ICMP_EXC_FRAGTIME:
                                    debugMsg += "[Fragment Reassembly Time Exceeded]"

                            # Type 12: Parameter Problem
                            elif icmpType == ICMP_PARAMETERPROB:

                                # Code 0: Pointer indicates the error
                                if icmpCode == ICMP_PARAM_PTR:
                                    debugMsg += "[Pointer indicates the error]"

                                # Code 1: Missing a Required Option
                                elif icmpCode == ICMP_PARAM_MRO:
                                    debugMsg += "[Missing a Required Option]"

                                # Code 2: Bad Length
                                elif icmpCode == ICMP_PARAM_BADLEN:
                                    debugMsg += "[Bad Length]"

                            # Unhandled Type
                            else:
                                debugMsg += "[Unhandled Type]"

                            # NOTE: displaying debug for every ping sent via traceroute is too messy, so it is not done
                            if self.__service == Service.PING:
                                print(debugMsg)

                    # ICMP Reply Packet had an invalid Checksum; discard
                    else:
                        print("ERROR: Invalid Checksum. [exp/act] = ", end='')
                        print(f"[{self.getIcmpReplyPacket().getPacketChecksum()}", end='/')
                        print(f"{self.getIcmpReplyPacket().getComputedChecksum()}]")

            except timeout:
                if self.__service == Service.PING:
                    print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

        def generateDetailedDebugMsg(self) -> None:
            # Display a detailed debug message showing all ICMP message fields and expected values.
            # Only to be used for ICMP Echo Reply messages, as reply messages have varying structures.
            # Reference: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol

            expCode: int = 0
            header: list = ["Status", "Field", "Expected", "Actual"]
            expTimestamp: float = struct.unpack("d", self.__data[:8])[0]

            # Extract ICMP message
            icmpReplyPacket = self.getIcmpReplyPacket()

            # Format: [Status]    Field    Expected    Actual
            print('\n' + 51 * '=' + " ICMP Packet Echo Reply " + 51 * '=')
            print(f"{header[0]:<8}{header[1]:<10}{header[2]:<53}    {header[3]:<53}")

            # Type
            if icmpReplyPacket.isValidIcmpType():
                print("[OK]    ", end='')
            else:
                print("[ERROR] ", end='')
            print("Type:     ", end='')
            print(f"{ICMP_ECHOREPLY:<53} || {icmpReplyPacket.getIcmpType():<53}")

            # Code
            if icmpReplyPacket.isValidIcmpCode():
                print("[OK]    ", end='')
            else:
                print("[ERROR] ", end='') 
            print("Code:     ", end='')
            print(f"{expCode:<53} || {icmpReplyPacket.getIcmpCode():<53}")

            # Checksum
            if icmpReplyPacket.isValidChecksum():
                print("[OK]    ", end='')
            else:
                print("[ERROR] ", end='')
            print("Checksum: ", end='')
            print(f"{icmpReplyPacket.getIcmpHeaderChecksum():<53} ", end='')
            print(f"|| {icmpReplyPacket.getComputedChecksum():<53}")

            # ID
            if icmpReplyPacket.isValidIcmpIdentifier():
                print("[OK]    ", end='')
            else:
                print("[ERROR] ", end='')
            print("ID:       ", end='')
            print(f"{self.getPacketIdentifier():<53} || {icmpReplyPacket.getIcmpIdentifier():<53}")

            # Sequence Number
            if icmpReplyPacket.isValidIcmpSequenceNumber():
                print("[OK]    ", end='') 
            else:
                print("[ERROR] ", end='')
            print("Sequence: ", end='')  
            print(f"{self.getPacketSequenceNumber():<53} || {icmpReplyPacket.getIcmpSequenceNumber():<53}")

            # Data: Timestamp
            if icmpReplyPacket.isValidDateTimeSent():
                print("[OK]    ", end='')
            else:
                print("[ERROR] ", end='')
            print("Time:     ", end='')
            print(f"{expTimestamp:<53} || {icmpReplyPacket.getDateTimeSent():<53}")

            # Data: Remaining
            if icmpReplyPacket.isValidIcmpData():
                print("[OK]    ", end='')
            else:
                print("[ERROR] ", end='')
            print("Data:     ", end='')
            print(f"{self.getDataRaw():<53} || {icmpReplyPacket.getIcmpData():<53}\n")


    ####################################################################################################################
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    ####################################################################################################################
    class IcmpPacket_EchoReply:
        ################################################################################################################
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        ################################################################################################################
        __recvPacket: bytes = b''
        __isValidResponse: bool = False
        __isValidIcmpType: bool = False
        __isValidIcmpCode: bool = False
        __isValidChecksum: bool = False
        __isValidIcmpIdentifier: bool = False
        __isValidIcmpSequenceNumber: bool = False
        __isValidDateTimeSent: bool = False
        __isValidIcmpData: bool = False
        __computedChecksum: int = 0
        __rtt: int = 0
        __errMsg: str = ''

        ################################################################################################################
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        ################################################################################################################
        def __init__(self, recvPacket: bytes) -> None:
            self.__recvPacket = recvPacket

        ################################################################################################################
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        ################################################################################################################
        def getRecvPacket(self) -> bytes:
            return self.__recvPacket

        def getIcmpType(self) -> int:
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self) -> int:
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self) -> int:
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self) -> int:
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self) -> int:
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self) -> float:
            # This accounts for bytes 28 through 35 = 64 bits
            return struct.unpack("d", self.__recvPacket[28:36])[0]   # Used to track overall round trip time
                                                                     # time.time() creates a 64 bit value of 8 bytes
        def getIcmpData(self) -> str:
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def getComputedChecksum(self) -> int:
            return self.__computedChecksum

        def getRtt(self) -> int:
            return self.__rtt

        def getErrMsgs(self) -> str:
            return self.__errMsg

        def isValidIcmpType(self) -> bool:
            return self.__isValidIcmpType

        def isValidIcmpCode(self) -> bool:
            return self.__isValidIcmpCode

        def isValidChecksum(self) -> bool:
            return self.__isValidChecksum

        def isValidIcmpSequenceNumber(self) -> bool:
            return self.__isValidIcmpSequenceNumber

        def isValidIcmpIdentifier(self) -> bool:
            return self.__isValidIcmpIdentifier

        def isValidDateTimeSent(self) -> bool:
            return self.__isValidDateTimeSent

        def isValidIcmpData(self) -> bool:
            return self.__isValidIcmpData

        def isValidResponse(self) -> bool:
            return self.__isValidResponse

        ################################################################################################################
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        ################################################################################################################
        def setIsValidIcmpCode(self, booleanValue: bool) -> None:
            self.__isValidIcmpCode = booleanValue

        def setIsValidIcmpType(self, booleanValue: bool) -> None:
            self.__isValidIcmpType = booleanValue

        def setIsValidChecksum(self, booleanValue: bool) -> None:
            self.__isValidChecksum = booleanValue

        def setIsValidIcmpSequenceNumber(self, booleanValue: bool) -> None:
            self.__isValidIcmpSequenceNumber = booleanValue

        def setIsValidIcmpIdentifier(self, booleanValue: bool) -> None:
            self.__isValidIcmpIdentifier = booleanValue

        def setIsValidIcmpData(self, booleanValue: bool) -> None:
            self.__isValidIcmpData = booleanValue

        def setIsValidDateTimeSent(self, booleanValue: bool) -> None:
            self.__isValidDateTimeSent = booleanValue

        def setIsValidResponse(self, booleanValue: bool) -> None:
            self.__isValidResponse = booleanValue

        def setRtt(self, rtt: int) -> None:
            self.__rtt = rtt

        def setErrMsg(self, msg: str) -> None:
            self.__errMsg = msg

        ################################################################################################################
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        ################################################################################################################
        def __unpackByFormatAndPosition(self, formatCode: str, basePosition: int):
            numberOfbytes: int = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        def __recalculateChecksum(self, reply: bytes) -> None:
            """
            Given an ICMP Echo Reply message, compute its checksum.

            Preconditions:
                1. Checksum field must be zeroed out before computing checksum.

            Similar to IcmpPacket.__recalculateChecksum()

            Source: http://www.networksorcery.com/enp/protocol/icmp/msg0.htm
            """

            checksum: int = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo: int = (len(reply) // 2) * 2

            # Calculate checksum for all paired segments
            count: int = 0
            while count < countTo:
                thisVal: int = reply[count + 1] * 256 + reply[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(reply):
                thisVal = reply[len(reply) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer: int = ~checksum             # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)

            self.__computedChecksum = answer

        ################################################################################################################
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        ################################################################################################################
        def validateChecksum(self) -> None:
            """
            Validate the ICMP Echo Reply checksum.

            Source: http://www.networksorcery.com/enp/protocol/icmp/msg0.htm
            """

            # Extract ICMP Echo Reply and zero out checksum.
            reply: bytes = self.__recvPacket[20:22] + struct.pack("!H", 0) + self.__recvPacket[24:]

            # Re-Calculate checksum.
            self.__recalculateChecksum(reply)

            # Compare with original checksum.
            if self.getIcmpHeaderChecksum() == self.__computedChecksum:
                self.__isValidChecksum = True 

        def printResultToConsole(self, ttl, timeReceived, addr):
            # Display error messages
            if not self.isValidResponse():
                print(f"\n{self.getErrMsgs()}")

            bytes = struct.calcsize("d")
            timeSent = self.getDateTimeSent()
            self.setRtt((timeReceived - timeSent) * 1000)
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      self.getRtt(),
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                 )

    ####################################################################################################################
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    ####################################################################################################################

    ####################################################################################################################
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    ####################################################################################################################
    __DEBUG_IcmpHelperLibrary = False                   # Allows for debug output

    ####################################################################################################################
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    ####################################################################################################################
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        # Sources: https://serverfault.com/questions/333116/what-does-mdev-mean-in-ping8
        #          https://serverfault.com/questions/999595/what-does-the-time-field-indicate-in-ping-statistics
        rtts: List[int] = []
        sentPckts: int = 0

        tStart: int = time.time()
        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()                                                # Build IP

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0

            sentPckts += 1
            if icmpPacket.getIcmpReplyPacket() is not None:
                rtts.append(icmpPacket.getIcmpReplyPacket().getRtt())
        tEnd: int = time.time()

        # Print stats
        print(f"\n--- {host} statistics ---")
        print(f"{sentPckts} packets transmitted, ", end='')
        print(f"{len(rtts)} received, ", end='')
        print(f"{(1 - (len(rtts) / sentPckts)) * 100:.0f}% packet loss, ", end='')
        print(f"time {(tEnd - tStart) * 1000:.0f} ms")
        if len(rtts) > 0:
            print("rtt min/avg/max/mdev = ", end='')
            print(f"{min(rtts):.3f}/{(sum(rtts) / len(rtts)):.3f}/{max(rtts):.3f}/{stdev(rtts):.3f} ms")

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        # References: 
        #     https://github.com/openbsd/src/blob/master/usr.sbin/traceroute/traceroute.c
        #     UNIX Network Programming

        # 30 hops max
        maxTtl: int = 30

        # 3 pings per hop
        numProbes: int = 3

        seq: int = 1

        print(f"traceroute to {host} ({gethostbyname(host.strip()) if len(host) > 0 else host}), {maxTtl} hops max")
        for ttl in range(1, maxTtl + 1):
            # Reference: (https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)
            destPort: int = 33434

            print(f"{ttl:2}  ", end='')

            # Send numProbes pings to destination
            for probe in range(1, numProbes + 1):

                # Build packet
                icmpPacket = IcmpHelperLibrary.IcmpPacket()
                icmpPacket.setService(Service.TRACEROUTE)

                # Build ICMP for IP payload
                icmpPacket.buildPacket_echoRequest((os.getpid() & 0xffff), seq)
                icmpPacket.setIcmpTarget(host)
                icmpPacket.setTtl(ttl)

                # Track when packet is being sent
                # NOTE: 
                #     Can't use reply header as ICMP Time Exceeded message is not same as ICMP Echo Reply
                # Reference: http://www.networksorcery.com/enp/protocol/icmp/msg11.htm
                tSend = time.time()

                # Sent packet
                icmpPacket.sendEchoRequest()

                # Timeout occurred
                if icmpPacket.getIcmpReplyPacket() is None:
                    print(" *", end=' ')
                    continue

                # Display hostname and IP address of current hop
                if probe == 1:
                    addr = icmpPacket.getRcvAddr()[0]
                    try:
                        hostname = gethostbyaddr(addr)[0]
                    except error:
                        hostname = addr
                    print(f"{hostname:52} {'(' + addr + ')':18}  ", end='')

                # Display RTT stats for current host
                print(f"{(icmpPacket.getRcvTime() - tSend) * 1000:8.3f} ms", end=' ')

                seq += 1

            # Reached destination
            if icmpPacket.getIcmpReplyPacket() is not None:
                if icmpPacket.getRcvAddr()[0] == icmpPacket.getDestinationIpAddress():
                    print()
                    return

            print()

    ####################################################################################################################
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    ####################################################################################################################
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


########################################################################################################################
# testPing()                                                                                                           #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
########################################################################################################################
def testPing():
    icmpHelperPing = IcmpHelperLibrary()

    icmpHelperPing.sendPing("127.0.0.1")
    print('=' * 100)
    icmpHelperPing.sendPing("209.233.126.254")
    print('=' * 100)
    icmpHelperPing.sendPing("sape.com.au")
    print('=' * 100)
    icmpHelperPing.sendPing("www.google.com")
    print('=' * 100)
    icmpHelperPing.sendPing("oregonstate.edu")
    print('=' * 100)
    icmpHelperPing.sendPing("gaia.cs.umass.edu")
    print('=' * 100)


########################################################################################################################
# testTraceroute()                                                                                                     #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
########################################################################################################################
def testTraceroute():
    icmpHelperPing = IcmpHelperLibrary()

    icmpHelperPing.traceRoute("oregonstate.edu")
    print('=' * 100)
    icmpHelperPing.traceRoute("google.com")
    print('=' * 100)
    icmpHelperPing.traceRoute("localhost")
    print()


########################################################################################################################
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
########################################################################################################################
def main():
    args = parser.parse_args()

    if args.action == "test":
        if args.value == "ping":
            return testPing()
        if args.value == "traceroute":
            return testTraceroute()

    if args.action == "ping":
        icmp = IcmpHelperLibrary()
        return icmp.sendPing(args.value)

    if args.action == "traceroute":
        icmp = IcmpHelperLibrary()
        return icmp.traceRoute(args.value)

    print("Usage: <action> <value>")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action")
    parser.add_argument("value")
    main()
