
"""
This script will calculate pdcp layer end-to-ed delay.
Usage: python getPdcpRtt.py [dir name] # Default dir name is current dir.
Output: ul_size, ul_fn_sfn, ul_timestamp, dl_size, dl_fn_sfn, dl_timestamp, first_dl_fn_sfn, dl_trans_delay, e2e_delay
"""

import sys
import os

def get_filepaths(directory):

    file_paths = []
    for root, directories, files in os.walk(directory):
        for filename in files:
            if filename.endswith(".txt"): # if filename[-7:] == "all.txt" and "1550" in filename:
                filepath = os.path.join(root, filename)
                file_paths.append(filepath)
    return file_paths

if __name__ == "__main__":
    if len(sys.argv) > 1:
        dir = sys.argv[1]
    else:
        dir = os.getcwd()
    filenames = get_filepaths(dir)
    print filenames

    ul_pkt = []
    dl_pkt = []
    last_sfn = []
    for filename in filenames:
        with open(filename, 'r') as f:
            is_pdcp_ul = False
            is_pdcp_dl = False
            timestamp = ''
            for line in f:
                # print is_pdsch_stat
                if line[:4] == '2017':
                    if "LTE PDCP UL Cipher Data PDU" in line:
                        is_pdcp_ul = True
                        timestamp = line[13:25]
                        ts = timestamp.split(':')
                        timestamp = int(ts[0]) * 3600 + int(ts[1]) * 60 + float(ts[2])
                    elif "LTE PDCP DL Cipher Data PDU" in line:
                        is_pdcp_dl = True
                        timestamp = line[13:25]
                        ts = timestamp.split(':')
                        timestamp = int(ts[0]) * 3600 + int(ts[1]) * 60 + float(ts[2])
                    else:
                        is_pdcp_ul = False
                        is_pdcp_dl = False
                elif is_pdcp_ul and '|' in line:
                    blocks = line.split('|')
                    if len(blocks) > 10 and blocks[2].replace(' ','').isdigit():
                        # print blocks
                        # break
                        size = int(blocks[7])
                        fn = int(blocks[9])
                        sfn = int(blocks[10])
                        if 68 < size < 100:
                            ul_pkt.append([size, fn * 10 + sfn, timestamp])

                elif is_pdcp_dl and '|' in line:
                    blocks = line.split('|')
                    if len(blocks) > 10 and blocks[9].replace(' ','').isdigit():
                        size = int(blocks[7])
                        fn = int(blocks[9])
                        sfn = int(blocks[10])
                        lens = len(last_sfn)
                        if size > 1000:
                            if lens < 16:
                                last_sfn.append(fn*10 + sfn)
                            else:
                                last_sfn.pop()
                                last_sfn.append(fn*10 + sfn)
                        if 68 < size < 100:
                            last_ts = last_sfn[0] if last_sfn != [] else (fn * 10 + sfn)
                            dl_pkt.append([size, fn * 10 + sfn, timestamp, last_ts, fn * 10 + sfn - last_ts])
                            last_sfn = []

    # print ul_pkt[0:120]
    # print dl_pkt[0:120]
    ul_pointer = 100 # [82, 111, 5, 77161.461]
    dl_pointer = 100 # [82, 113, 1, 77161.466]
    joint_delay = []
    while ul_pointer < len(ul_pkt) and dl_pointer < len(dl_pkt):
        # print ul_pkt[ul_pointer] + dl_pkt[dl_pointer]
        ul_ts = ul_pkt[ul_pointer][2]
        dl_ts = dl_pkt[dl_pointer][2]
        # print ul_pkt[ul_pointer] + dl_pkt[dl_pointer]

        ul_sfn = ul_pkt[ul_pointer][1]
        dl_sfn = dl_pkt[dl_pointer][1]

        if dl_ts - ul_ts > 1:
            ul_pointer += 1
            continue
        elif ul_ts - dl_ts > 1:
            dl_pointer += 1
            continue

        if ul_sfn - dl_sfn > 500 or -9740 < ul_sfn - dl_sfn < -8000:
            dl_pointer += 1
            continue
        elif dl_sfn - ul_sfn > 500 or -9740 < dl_sfn - ul_sfn < -8000:
            ul_pointer += 1
            continue


        ul_size = ul_pkt[ul_pointer][0]
        dl_size = dl_pkt[dl_pointer][0]
        if ul_size == dl_size:
            joint_delay.append(ul_pkt[ul_pointer] + dl_pkt[dl_pointer])
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

