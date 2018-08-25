import os
import sys
 
 
# Import MobileInsight modules
from mobile_insight.analyzer import MsgLogger,LteRlcAnalyzer
from mobile_insight.monitor import OfflineReplayer
from xml.dom import minidom
class DumpAnalyzer(LteRlcAnalyzer):
 
    def __init__(self):
        LteRlcAnalyzer.__init__(self)
 
        self.add_source_callback(self.__msg_callback)
        self.mi2log = ""
 
    def close(self):
        print "End"
        pass
 
    def set_mi2log(self, path):
        self.mi2log = path
 
    def set_source(self,source):
        """
        Set the trace source. Enable the cellular signaling messages
 
        :param source: the trace source (collector).
        """
        LteRlcAnalyzer.set_source(self,source)
  
    def __msg_callback(self,msg):
	print msg.data.decode()
        
if __name__ == "__main__":
 
    if len(sys.argv) != 2:
        print "Usage python example_pdcp.py [path to mi2log file]"
        exit()
 
    # Initialize a 3G/4G monitor
    src = OfflineReplayer()
    src.set_input_path(sys.argv[1])
    #logger= MsgLogger()
    #logger.set_decode_format(MsgLogger.DICT)
    #logger.set_dump_type(MsgLogger.FILE_ONLY)
    #logger.save_decoded_msg_as("./Dump.txt")
    #logger.set_source(src)

    dumpAnalyzer = DumpAnalyzer()
    dumpAnalyzer.set_source(src)
 
    src.run()

