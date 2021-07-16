########################################################################################################################
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
########################################################################################################################
import os
import select
from socket import *
from statistics import stdev 
import struct
import sys
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
# IcmpType                                                                                                             #
#                                                                                                                      #
# References:                                                                                                          #
# http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                                #
# http://sites.uclouvain.be/SystInfo/usr/include/netinet/ip_icmp.h.html                                                #
########################################################################################################################
ICMP_ECHOREPLY       = 0    # Echo Reply
ICMP_DEST_UNREACH    = 3    # Destination Unreachable
ICMP_REDIRECT        = 5    # Redirect (change route)
ICMP_ECHO            = 8    # Echo Request
ICMP_ROUTERADVERT    = 9    # Router Advertisement
ICMP_ROUTERSOLICIT   = 10   # Router Solicitation
ICMP_TIME_EXCEEDED   = 11   # Time Exceeded
ICMP_PARAMETERPROB   = 12   # Parameter Problem
ICMP_TIMESTAMP       = 13   # Timestamp Request
ICMP_TIMESTAMPREPLY  = 14   # Timestamp Reply
ICMP_PHOTURIS        = 40   # Photuris
ICMP_EXT_ECHO        = 42   # Extended Echo Request
ICMP_EXT_ECHOREPLY   = 43   # Extended Echo Reply

########################################################################################################################
# IcmpCode                                                                                                             #
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

# Codes for ROUTERADVERT
ICMP_ADVERT          = 0    # Normal router advertisement
ICMP_ADVERT_DNR      = 16   # Does not route common traffic

# Codes for TIME_EXCEEDED
ICMP_EXC_TTL         = 0    # TTL Exceeded in Transit
ICMP_EXC_FRAGTIME    = 1    # Fragment Reassembly Time Exceeded

# Codes for PARAMETERPROB 
ICMP_PARAM_PTR       = 0    # Pointer indicates the error
ICMP_PARAM_MRO       = 1    # Missing a Required Option
ICMP_PARAM_BADLEN    = 2    # Bad Length

# Codes for PHOTURIS 
ICMP_PHOT_BADSPI     = 0    # Bad SPI
ICMP_PHOT_AUTHFAIL   = 1    # Authentication Failed
ICMP_PHOT_DCMPFAIL   = 2    # Decompression Failed
ICMP_PHOT_DCRYPTFAIL = 3    # Decryption Failed
ICMP_PHOT_NEEDAUTHEN = 4    # Need Authentication
ICMP_PHOT_NEEDAUTH   = 5    # Need Authorization

# Codes for EXT_ECHO
ICMP_EXTECHO         = 0    # No Error

# Codes for EXT_ECHOREPLY 
ICMP_EXTREPLY        = 0    # No Error
ICMP_EXTREPLY_QUERY  = 1    # Malformed Query
ICMP_EXTREPLY_IFACE  = 2    # No Such Interface
ICMP_EXTREPLY_ENTRY  = 3    # No Such Table Entry
ICMP_EXTREPLY_MISQ   = 4    # Multiple Interfaces Satisfy Query


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
        __icmpTarget: str = ""                # Remote Host
        __destinationIpAddress: str = ""      # Remote Host IP Address
        __header: bytes = b''                 # Header after byte packing
        __data: bytes = b''                   # Data after encoding
        __dataRaw: str = ""                   # Raw string data before encoding
        __icmpType: int = 0                   # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode: int = 0                   # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum: int = 0             # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier: int = 0           # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber: int = 0       # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout: int = 30
        __ttl: int = 255                      # Time to live
        __icmpReplyPacket = None              # ICMP reply packet

        __DEBUG_IcmpPacket: bool = False      # Allows for debug output

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
            # Track err messages
            err: str = ''

            # ICMP Echo Reply should have a Type = 0 and Code = 0
            # Source: 
            expType: int = 0
            expCode: int = 0

            # Validate each field in ICMP Echo Reply message

            # Check if Type = 0 
            if icmpReplyPacket.getIcmpType() == expType:
                icmpReplyPacket.setIsValidIcmpType(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)
                err += "ERROR: Invalid ICMP Type\n"
                err += f"\tExpected: {expType}\n"
                err += f"\tActual:   {icmpReplyPacket.getIcmpType()}\n\n"

            # Check if Code = 0
            if icmpReplyPacket.getIcmpCode() == expCode:
                icmpReplyPacket.setIsValidIcmpCode(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)
                err += "ERROR: Invalid ICMP Code\n"
                err += f"\tExpected: {expCode}\n"
                err += f"\tActual:   {icmpReplyPacket.getIcmpCode()}\n\n"

            # Check for any bit errors
            icmpReplyPacket.validateChecksum()
            if not icmpReplyPacket.isValidChecksum():
                err += "ERROR: Invalid Header Checksum\n"
                err += f"\tExpected: {icmpReplyPacket.getIcmpHeaderChecksum()}\n"
                err += f"\tActual:   {icmpReplyPacket.getComputedChecksum()}\n\n"

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

            # Check if ICMP Echo Request Data = ICMP Echo Reply Data
            if self.getDataRaw() == icmpReplyPacket.getIcmpData():
                icmpReplyPacket.setIsValidIcmpData(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)
                err += "ERROR: Invalid Data\n"
                err += f"\tExpected: {self.getDataRaw()}\n"
                err += f"\tActual:   {icmpReplyPacket.getIcmpData()}\n"

            icmpReplyPacket.addErrMsg(err)

            # Format:
            # [Status]    Field    Expected    Actual
            print('\n' + 51 * '=' + " ICMP Packet Echo Reply " + 51 * '=', file=sys.stderr)
            print("Status" + '\t' + "Field" + 3 * '\t' + "Expected" + 24 * '\t' + " Actual", file=sys.stderr)

            # Type
            if icmpReplyPacket.isValidIcmpType():
                print("[OK]    ", end='', file=sys.stderr)
            else:
                print("[ERROR] ", end='', file=sys.stderr)
            print("Type:     ", end='', file=sys.stderr)
            print(f"{expType:<53} || {icmpReplyPacket.getIcmpType():<53}", file=sys.stderr)

            # Code
            if icmpReplyPacket.isValidIcmpCode():
                print("[OK]    ", end='', file=sys.stderr)
            else:
                print("[ERROR] ", end='', file=sys.stderr)
            print("Code:     ", end='', file=sys.stderr)
            print(f"{expCode:<53} || {icmpReplyPacket.getIcmpCode():<53}", file=sys.stderr)

            # Checksum
            if icmpReplyPacket.isValidChecksum():
                print("[OK]    ", end='', file=sys.stderr)
            else:
                print("[ERROR] ", end='', file=sys.stderr)
            print("Checksum: ", end='', file=sys.stderr)
            print(f"{icmpReplyPacket.getIcmpHeaderChecksum():<53} ", end='', file=sys.stderr)
            print(f"|| {icmpReplyPacket.getComputedChecksum():<53}", file=sys.stderr)

            # ID
            if icmpReplyPacket.isValidIcmpIdentifier():
                print("[OK]    ", end='', file=sys.stderr)
            else:
                print("[ERROR] ", end='', file=sys.stderr)
            print("ID:       ", end='', file=sys.stderr)
            print(f"{self.getPacketIdentifier():<53} || {icmpReplyPacket.getIcmpIdentifier():<53}", file=sys.stderr)

            # Sequence Number
            if icmpReplyPacket.isValidIcmpSequenceNumber():
                print("[OK]    ", end='', file=sys.stderr)
            else:
                print("[ERROR] ", end='', file=sys.stderr)
            print("Sequence: ", end='', file=sys.stderr)  
            print(f"{self.getPacketSequenceNumber():<53} || {icmpReplyPacket.getIcmpSequenceNumber():<53}",
                  file=sys.stderr)

            # Data
            if icmpReplyPacket.isValidIcmpData():
                print("[OK]    ", end='', file=sys.stderr)
            else:
                print("[ERROR] ", end='', file=sys.stderr)
            print("Data:     ", end='', file=sys.stderr)
            print(f"{self.getDataRaw():<53} || {icmpReplyPacket.getIcmpData():<53}\n", file=sys.stderr)

            # Set isValidResponse flag to True if all fields valid
            if icmpReplyPacket.isValidIcmpType() and icmpReplyPacket.isValidIcmpCode() and \
                    icmpReplyPacket.isValidChecksum() and icmpReplyPacket.isValidIcmpIdentifier() and \
                    icmpReplyPacket.isValidIcmpSequenceNumber() and icmpReplyPacket.isValidIcmpData():
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
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

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
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    # Type 0: Echo Reply
                    if icmpType == ICMP_ECHOREPLY:
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.setIcmpReplyPacket(icmpReplyPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)

                        # Code 0: No Code 
                        if icmpCode == 0:
                            pass

                        # Invalid Code
                        else:
                            pass

                        return      # Echo reply is the end and therefore should return

                    # Type 3: Destination Unreachable
                    elif icmpType == ICMP_DEST_UNREACH:
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )

                        # Code 0: Network Unreachable
                        if icmpCode == ICMP_NET_UNREACH:
                            pass

                        # Code 1: Host Unreachable
                        elif icmpCode == ICMP_HOST_UNREACH:
                            pass

                        # Code 2: Protocol Unreachable
                        elif icmpCode == ICMP_PROT_UNREACH:
                            pass

                        # Code 3: Port Unreachable
                        elif icmpCode == ICMP_PORT_UNREACH:
                            pass

                        # Code 4: Fragmentation Needed/DF Set
                        elif icmpCode == ICMP_FRAG_NEEDED:
                            pass

                        # Code 5: Source Route failed
                        elif icmpCode == ICMP_SR_FAILED:
                            pass

                        # Code 6: Destination Network Unknown
                        elif icmpCode == ICMP_NET_UNKNOWN:
                            pass

                        # Code 7: Destination Host Unknown
                        elif icmpCode == ICMP_HOST_UNKNOWN:
                            pass

                        # Code 8: Source Host Isolated
                        elif icmpCode == ICMP_HOST_ISOLATED:
                            pass

                        # Code 9: Communication with Destination Network Administratively Prohibited
                        elif icmpCode == ICMP_NET_ANO:
                            pass

                        # Code 10: Communication with Destination Host Administratively Prohibited
                        elif icmpCode == ICMP_HOST_ANO:
                            pass

                        # Code 11: Destination Network Unreachable for Type of Service
                        elif icmpCode == ICMP_NET_UNR_TOS:
                            pass

                        # Code 12: Destination Host Unreachable for Type of Service
                        elif icmpCode == ICMP_HOST_UNR_TOS:
                            pass

                        # Code 13: Communication Administratively Prohibited (packet filtered)
                        elif icmpCode == ICMP_PKT_FILTERED:
                            pass

                        # Code 14: Host Precedence violation
                        elif icmpCode == ICMP_PREC_VIOLATION:
                            pass

                        # Code 15: Precedence cutoff in effect
                        elif icmpCode == ICMP_PREC_CUTOFF:
                            pass

                        # Invalid Code
                        else:
                            pass

                    # Type 5: Redirect
                    elif icmpType == ICMP_REDIRECT:
                        # Code 0: Redirect Datagram for the Network (or subnet)
                        if icmpCode == ICMP_REDIR_NET:
                            pass

                        # Code 1: Redirect Datagram for the Host
                        elif icmpCode == ICMP_REDIR_HOST:
                            pass

                        # Code 2: Redirect Datagram for TOS and Network
                        elif icmpCode == ICMP_REDIR_NETTOS:
                            pass

                        # Code 3: Redirect Datagram for TOS and Host
                        elif icmpCode == ICMP_REDIR_HOSTTOS:
                            pass

                        # Invalid Code
                        else:
                            pass

                    # Type 8: Echo Request
                    elif icmpType == ICMP_ECHO:
                        # Code 0: No Code
                        if icmpCode == 0:
                            pass

                        # Invalid Code
                        else:
                            pass

                    # Type 9: Router Advertisement
                    elif icmpType == ICMP_ROUTERADVERT:
                        # Code 0: Normal router advertisement
                        if icmpCode == ICMP_ADVERT:
                            pass

                        # Code 16: Does not route common traffic
                        elif icmpCode == ICMP_ADVERT_DNR:
                            pass

                        # Invalid Code
                        else:
                            pass

                    # Type 10: Router Solicitation
                    elif icmpType == ICMP_ROUTERSOLICIT:
                        # Code 0: No Code
                        if icmpCode == 0:
                            pass

                        # Invalid Code
                        else:
                            pass

                    # Type 11: Time Exceeded
                    elif icmpType == ICMP_TIME_EXCEEDED:
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              )

                        # Code 0: TTL Exceeded in Transit
                        if icmpCode == ICMP_EXC_TTL:
                            pass

                        # Code 1: Fragment Reassembly Time Exceeded
                        elif icmpCode == ICMP_EXC_FRAGTIME:
                            pass

                        # Invalid Code
                        else:
                            pass

                    # Type 12: Parameter Problem
                    elif icmpType == ICMP_PARAMETERPROB:
                        # Code 0: Pointer indicates the error
                        if icmpCode == ICMP_PARAM_PTR:
                            pass

                        # Code 1: Missing a Required Option
                        elif icmpCode == ICMP_PARAM_MRO:
                            pass

                        # Code 2: Bad Length
                        elif icmpCode == ICMP_PARAM_BADLEN:
                            pass

                        # Invalid Code
                        else:
                            pass

                    # Type 13: Timestamp Request
                    elif icmpType == ICMP_TIMESTAMP:
                        # Code 0: No Code
                        if icmpCode == 0:
                            pass

                        # Invalid Code
                        else:
                            pass

                    # Type 14: Timestamp Reply
                    elif icmpType == ICMP_TIMESTAMPREPLY:
                        # Code 0: No Code
                        if icmpCode == 0:
                            pass

                        # Invalid Code
                        else:
                            pass

                    # Type 40: Photuris
                    elif icmpType == ICMP_PHOTURIS:
                        # Code 0: Bad SPI
                        if icmpCode == ICMP_PHOT_BADSPI:
                            pass

                        # Code 1: Malformed Query
                        elif icmpCode == ICMP_PHOT_AUTHFAIL:
                            pass

                        # Code 2: Decompression Failed 
                        elif icmpCode == ICMP_PHOT_DCMPFAIL:
                            pass

                        # Code 3: Decryption Failed
                        elif icmpCode == ICMP_PHOT_DCRYPTFAIL:
                            pass

                        # Code 4: Need Authentication
                        elif icmpCode == ICMP_PHOT_NEEDAUTHEN:
                            pass

                        # Code 5: Need Authorization
                        elif icmpCode == ICMP_PHOT_NEEDAUTH:
                            pass

                        # Invalid Code
                        else:
                            pass

                    # Type 42: Extended Echo Request
                    elif icmpType == ICMP_EXT_ECHO:
                        # Code 0: No Error
                        if icmpCode == ICMP_EXTECHO:
                            pass

                        # Code 1-255: Unassigned
                        else:
                            pass

                    # Type 43: Extended Echo Reply
                    elif icmpType == ICMP_EXT_ECHOREPLY:
                        # Code 0: No Error
                        if icmpCode == ICMP_EXTREPLY:
                            pass

                        # Code 1: Malformed Query
                        elif icmpCode == ICMP_EXTREPLY_QUERY:
                            pass

                        # Code 2: No Such Interface
                        elif icmpCode == ICMP_EXTREPLY_IFACE:
                            pass

                        # Code 3: No Such Table Entry
                        elif icmpCode == ICMP_EXTREPLY_ENTRY:
                            pass

                        # Code 4: Multiple Interfaces Satisfy Query
                        elif icmpCode == ICMP_EXTREPLY_MISQ:
                            pass

                        # Code 5-255: Unassigned
                        else:
                            pass

                    # Invalid Type
                    else:
                        print("error")
            except timeout:
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
        __isValidIcmpData: bool = False
        __computedChecksum: int = 0
        __rtt: int = 0
        __errMsgs: str = ''

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

        def getDateTimeSent(self) -> int:
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes
        def getIcmpData(self) -> str:
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def getComputedChecksum(self) -> int:
            return self.__computedChecksum

        def getRtt(self) -> int:
            return self.__rtt

        def getErrMsgs(self) -> str:
            return self.__errMsgs

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

        def setIsValidResponse(self, booleanValue: bool) -> None:
            self.__isValidResponse = booleanValue

        def setRtt(self, rtt: int) -> None:
            self.__rtt = rtt

        def addErrMsg(self, msg: str) -> None:
            self.__errMsgs += msg

        ################################################################################################################
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        ################################################################################################################
        def __unpackByFormatAndPosition(self, formatCode: str, basePosition: int) -> int:
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
            if self.getIcmpHeaderChecksum() != self.__computedChecksum:
                self.__isValidChecksum = False
            else:
                self.__isValidChecksum = True 

        def printResultToConsole(self, ttl, timeReceived, addr):
            # Display error messages
            if not self.isValidResponse():
                print(f"\n{self.getErrMsgs()}")

            # TODO
            # Modify output to correspond to the way a standard ping program works. 
            # Report minimum, maximum, and average RTTs at the end of all pings from client.
            # Calculate packet loss rate (in percentage).

            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
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
            # TODO
            # we should be confirming values are correct, such as identifier and sequence number and data
            # Parse ICMP response error codes and display corresponding error results to user.

            sentPckts += 1
            if icmpPacket.getIcmpReplyPacket() is not None:
                rtts.append(icmpPacket.getIcmpReplyPacket().getRtt())

        tEnd: int = time.time()
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
        # TODO
        # Build code for trace route here

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
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
########################################################################################################################
def main():
    icmpHelperPing = IcmpHelperLibrary()


    # Choose one of the following by uncommenting out the line
    icmpHelperPing.sendPing("209.233.126.254")
    icmpHelperPing.sendPing("sape.com.au")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("oregonstate.edu")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("oregonstate.edu")


if __name__ == "__main__":
    main()
