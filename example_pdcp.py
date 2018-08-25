#!/usr/bin/python
# Filename: offline-analysis-example.py
import os
import sys
<<<<<<< HEAD

from datetime import timedelta
 
||||||| merged common ancestors
 
=======

>>>>>>> 939536a8cb4e10a627cb9c7ea9c4003d6a48c317
"""
Offline analysis by replaying logs
"""

# Import MobileInsight modules
from mobile_insight.analyzer import Analyzer
from mobile_insight.monitor import OfflineReplayer
from xml.dom import minidom


class DumpAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.add_source_callback(self.__msg_callback)
        self.mi2log = ""
<<<<<<< HEAD
        self.ul_pkt = []
        self.dl_pkt = []
        self.last_sfn = []
 
||||||| merged common ancestors
 
=======

>>>>>>> 939536a8cb4e10a627cb9c7ea9c4003d6a48c317
    def close(self):
        print
        "End"
        pass

    def set_mi2log(self, path):
        self.mi2log = path

    def set_source(self, source):
        """
        Set the trace source. Enable the cellular signaling messages

        :param source: the trace source (collector).
        """
        Analyzer.set_source(self, source)

        # source.enable_log("LTE_RRC_OTA_Packet")
        # source.enable_log("LTE_RRC_Serv_Cell_Info")
        # source.enable_log("LTE_RRC_MIB_Packet")
        # source.enable_log("LTE_RRC_MIB_Message_Log_Packet")
        # source.enable_log("LTE_NAS_ESM_State")
        # source.enable_log("LTE_NAS_ESM_OTA_Incoming_Packet")
        # source.enable_log("LTE_NAS_ESM_OTA_Outgoing_Packet")
        # source.enable_log("LTE_NAS_EMM_State")
        # source.enable_log("LTE_NAS_EMM_OTA_Incoming_Packet")
        # source.enable_log("LTE_NAS_EMM_OTA_Outgoing_Packet")

        # source.enable_log("LTE_PDCP_DL_Config")
        # source.enable_log("LTE_PDCP_UL_Config")
        # source.enable_log("LTE_PDCP_UL_Data_PDU")
        # source.enable_log("LTE_PDCP_DL_Ctrl_PDU")
        # source.enable_log("LTE_PDCP_UL_Ctrl_PDU")
        # source.enable_log("LTE_PDCP_DL_Stats")
        # source.enable_log("LTE_PDCP_UL_Stats")
        # source.enable_log("LTE_PDCP_DL_SRB_Integrity_Data_PDU")
        # source.enable_log("LTE_PDCP_UL_SRB_Integrity_Data_PDU")

        source.enable_log("LTE_PDCP_DL_Cipher_Data_PDU")
        source.enable_log("LTE_PDCP_UL_Cipher_Data_PDU")

        # source.enable_log("LTE_RLC_UL_Config_Log_Packet")
        # source.enable_log("LTE_RLC_DL_Config_Log_Packet")
        source.enable_log("LTE_RLC_UL_AM_All_PDU")
        source.enable_log("LTE_RLC_DL_AM_All_PDU")
        # source.enable_log("LTE_RLC_UL_Stats")
        # source.enable_log("LTE_RLC_DL_Stats")

        # source.enable_log("LTE_MAC_Configuration")
        # source.enable_log("LTE_MAC_UL_Transport_Block")
        # source.enable_log("LTE_MAC_DL_Transport_Block")
        # source.enable_log("LTE_MAC_UL_Buffer_Status_Internal")
        # source.enable_log("LTE_MAC_UL_Tx_Statistics")
        # source.enable_log("LTE_MAC_Rach_Trigger")
        # source.enable_log("LTE_MAC_Rach_Attempt")

        # source.enable_log("LTE_PHY_PDSCH_Packet")
        # source.enable_log("LTE_PHY_Serv_Cell_Measurement")
        # source.enable_log("LTE_PHY_Connected_Mode_Intra_Freq_Meas")
        # source.enable_log("LTE_PHY_Inter_RAT_Measurement")
        # source.enable_log("LTE_PHY_Inter_RAT_CDMA_Measurement")
        # source.enable_log("LTE_PHY_Idle_Neighbor_Cell_Meas")
        # source.enable_log("LTE_PHY_Connected_Mode_Neighbor_Measurement")

        # source.enable_log("LTE_PHY_PUCCH_Power_Control")
        # source.enable_log("LTE_PHY_PUSCH_Power_Control")
        # source.enable_log("LTE_PHY_PDCCH_PHICH_Indication_Report")
        # source.enable_log("LTE_PHY_PDSCH_Stat_Indication")
        # source.enable_log("LTE_PHY_System_Scan_Results")
        # source.enable_log("LTE_PHY_BPLMN_Cell_Request")
        # source.enable_log("LTE_PHY_BPLMN_Cell_Confirm")
        # source.enable_log("LTE_PHY_Serving_Cell_COM_Loop")
        # source.enable_log("LTE_PHY_PDCCH_Decoding_Result")
        # source.enable_log("LTE_PHY_PDSCH_Decoding_Result")
        # source.enable_log("LTE_PHY_PUSCH_Tx_Report")
        # source.enable_log("LTE_PHY_PUCCH_Tx_Report")
        # source.enable_log("LTE_PHY_RLM_Report")
        # source.enable_log("LTE_PHY_PUSCH_CSF")
        # source.enable_log("LTE_RRC_CDRX_Events_Info")
        # source.enable_log("WCDMA_RRC_States")

        # source.enable_log("CDMA_Paging_Channel_Message")

        # source.enable_log("1xEV_Rx_Partial_MultiRLP_Packet")
        # source.enable_log("1xEV_Connected_State_Search_Info")
        # source.enable_log("1xEV_Signaling_Control_Channel_Broadcast")
        # source.enable_log("1xEV_Connection_Attempt")
        # source.enable_log("1xEV_Connection_Release")

        # source.enable_log("WCDMA_RRC_OTA_Packet")
        # source.enable_log("WCDMA_RRC_Serv_Cell_Info")
        # source.enable_log("WCDMA_Search_Cell_Reselection_Rank")

        # source.enable_log("UMTS_NAS_OTA_Packet")
        # source.enable_log("UMTS_NAS_GMM_State")
        # source.enable_log("UMTS_NAS_MM_State")
        # source.enable_log("UMTS_NAS_MM_REG_State")

        # source.enable_log("GSM_RR_Cell_Information")
        # source.enable_log("GSM_Surround_Cell_BA_List");
        # source.enable_log("GSM_RR_Cell_Reselection_Meas");
        # source.enable_log("GSM_RR_Cell_Reselection_Parameters");

        # source.enable_log("GSM_DSDS_RR_Cell_Information")
        # source.enable_log("GSM_DSDS_RR_Cell_Reselection_Parameters");

        # source.enable_log("Srch_TNG_1x_Searcher_Dump");
        # source.enable_log("_1xEVDO_Multi_Carrier_Pilot_Sets");
 
 
    def __msg_callback(self,msg):
        if msg.type_id == "LTE_PDCP_DL_Cipher_Data_PDU":
            log_item = msg.data.decode()
            if 'Subpackets' in log_item and len(log_item['Subpackets']) > 0:
                subPkt = log_item['Subpackets'][0]
                listPDU = subPkt['PDCPDL CIPH DATA']
                for pduItem in listPDU:
                    sn = int(pduItem['SN'])
                    sys_fn = int(pduItem['Sys FN'])
                    sub_fn = int(pduItem['Sub FN'])
                    # hdr_len = int(pduItem['logged_bytes'])  # rlc_pdu_size = pdcp_pdu_size + rlc_hdr_len
                    sdu_size = int(pduItem['PDU Size']) #  - hdr_len
                    tot_fn = 10 * sys_fn + sub_fn
                    timestamp = log_item['timestamp'] # Datetime
                    if sdu_size > 1000:
                        if len(self.last_sfn) < 16:
                            self.last_sfn.append(tot_fn)
                        else:
                            self.last_sfn.pop()
                            self.last_sfn.append(tot_fn)

                    if 68 < sdu_size < 100:
                        last_ts = self.last_sfn[0] if len(self.last_sfn) > 0 else tot_fn
                        self.dl_pkt.append([sdu_size, tot_fn, timestamp, last_ts, tot_fn - last_ts])
                        self.last_sfn = []

                    print sn, sys_fn, sub_fn, sdu_size

        elif msg.type_id == "LTE_PDCP_UL_Cipher_Data_PDU":
            log_item = msg.data.decode()
            if 'Subpackets' in log_item and len(log_item['Subpackets']) > 0:
                subPkt = log_item['Subpackets'][0]
                listPDU = subPkt['PDCPUL CIPH DATA']
                for pduItem in listPDU:
                    sn = int(pduItem['SN'])
                    sys_fn = int(pduItem['Sys FN'])
                    sub_fn = int(pduItem['Sub FN'])
                    # hdr_len = int(pduItem['logged_bytes'])  # rlc_pdu_size = pdcp_pdu_size + rlc_hdr_len
                    sdu_size = int(pduItem['PDU Size']) #  - hdr_len
                    
                    timestamp = log_item['timestamp'] # Datetime
                    print sn, sys_fn, sub_fn, sdu_size, timestamp

                    if 68 < sdu_size < 100:
                        self.ul_pkt.append([sdu_size, sys_fn * 10 + sub_fn, timestamp])

        elif msg.type_id == "LTE_RLC_UL_AM_All_PDU":
            print "oko"

        elif msg.type_id == "LTE_RLC_DL_AM_All_PDU":
            print "kko"
        
    def post_process(self):
        print len(self.ul_pkt)
        print len(self.dl_pkt)
        ul_pointer = 0
        dl_pointer = 0
        joint_delay = []

        while ul_pointer < len(self.ul_pkt) and dl_pointer < len(self.dl_pkt):
            ul_ts = self.ul_pkt[ul_pointer][2]
            dl_ts = self.dl_pkt[dl_pointer][2]

            ul_sfn = self.ul_pkt[ul_pointer][1]
            dl_sfn = self.dl_pkt[dl_pointer][1]

            if dl_ts - ul_ts > timedelta(seconds=1):
                ul_pointer += 1
                continue
            elif ul_ts - dl_ts > timedelta(seconds=1):
                dl_pointer += 1
                continue

            if ul_sfn - dl_sfn > 500 or -9740 < ul_sfn - dl_sfn < -8000:
                dl_pointer += 1
                print("JHojoj")
                continue
            elif dl_sfn - ul_sfn > 500 or -9740 < dl_sfn - ul_sfn < -8000:
                ul_pointer += 1
                print("OP")
                continue

            ul_size = self.ul_pkt[ul_pointer][0]
            dl_size = self.dl_pkt[dl_pointer][0]
            print(ul_size, dl_size)
            if ul_size == dl_size:
                joint_delay.append(self.ul_pkt[ul_pointer] + self.dl_pkt[dl_pointer])
                dl_pointer += 1
                ul_pointer += 1
            elif (dl_size < ul_size and not (dl_size < 75 and ul_size > 94)) or (ul_size < 75 and dl_size > 94 and (ul_sfn > dl_sfn or ul_sfn - dl_sfn < -8000)):
                dl_pointer += 1
            else:
                ul_pointer += 1

        print "ul_size, ul_fn_sfn, ul_timestamp, dl_size, dl_fn_sfn, dl_timestamp, first_dl_fn_sfn, dl_trans_delay, e2e_delay"
        for i in joint_delay:
            if 0 < i[4] - i[1] < 600:
                print ','.join(map(str, i + [i[4] - i[1]]))

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print
        "Usage python example_pdcp.py [path to mi2log file]"
        exit()

    # Initialize a 3G/4G monitor
    src = OfflineReplayer()
    src.set_input_path(sys.argv[1])

    dumpAnalyzer = DumpAnalyzer()
    dumpAnalyzer.set_source(src)

    # Start the monitoring
    src.run()

    dumpAnalyzer.post_process()