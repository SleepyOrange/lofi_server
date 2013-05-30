__author__ = 'skyahead'

import os
import subprocess
import pdb
import glob
import socket
import logging
from datetime import datetime
from time import sleep
import heapq
from pymongo import MongoClient

# GLOBAL CONSTANTS
LOG_FILE_DIR = "/home/skyahead/Lofi/logfiles/"
TEMP_FILE_DIR = "/tmp/logs/*.pcap"
MY_PHONE_IP = '10.220.10.85'
MY_PHONE_UDP_PORT = 55555
UDP_DELIMITER = '61616161616161616161'
WARMUP_STEP_SIZE_IN_PKTS = 2  # start feedbacking to phones after this num of udp received
TRAINING_START_FLAG = False
TRAINING_TIME = 5  # the duration in seconds to train a location
LONGEST_WAITING_TIME_PER_PHONE = 2  # max seconds the server should have got at least 10 udp from a phone
TRAINING_PKT_TYPE = '0'
WORKING_PKT_TYPE = '1'

# GLOBAL VARIABLES
num_of_pkts = [0, 0]  # num of pkts got so far
dbm_sum = [0.0, 0.0]
w = 0.2  # exponential smoothing weight, i.e., dbm_sum = dbm_sum * (1-w) + curr_dbm * w
last_seen = [datetime.now(), datetime.now()]  # last time a pkt is seen by the server


def setup_logging():
    global log
    #http://docs.python.org/2/howto/logging-cookbook.html#logging-to-multiple-destinations
    DATEFMT = '%Y-%m-%d %H:%M'
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                        datefmt=DATEFMT,
                        filename='./log.txt',
                        filemode='a')

    # define a Handler which writes INFO messages or higher to the sys.stderr
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)

    # set a format which is simpler for console use
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s  %(message)s', DATEFMT)

    # tell the handler to use this format
    console.setFormatter(formatter)

    # add the handler to the root logger
    logging.getLogger('').addHandler(console)

    # define logger for this lofi server
    log = logging.getLogger('lofiLogger')


def reset_last_seen():
    global last_seen
    last_seen = [datetime.now(), datetime.now()]


def open_mongo():
    # open mongo
    connection = MongoClient()
    db = connection.lofi_db
    return db


def match_location(db):
    # find the closet match between dbm_sum and mongo
    global dbm_sum
    roomIDs, rss1s, rss2s = read_rss(db)
    locIDArray = []
    distArray = []
    for idx, one_loc in enumerate(roomIDs):
        dist1 = abs(dbm_sum[0] - rss1s[idx])
        dist2 = abs(dbm_sum[1] - rss2s[idx])
        locIDArray.append(idx)
        distArray.append(dist1 + dist2)

    nlesser_items = heapq.nsmallest(2, distArray)
    roomID_1 = roomIDs[distArray.index(nlesser_items[0])]
    roomID_2 = roomIDs[distArray.index(nlesser_items[1])]

    if roomID_1 > roomID_2:

        roomID_1, roomID_2 = roomID_2, roomID_1

    return str(roomID_1) + ' ' + str(roomID_2)


def read_rss(db):
    # read rss from db
    all_rss = db.metrics.find()
    roomIdArray = []
    rssAP1Array = []
    rssAP2Array = []
    for one_rss in all_rss:
        roomIdArray.append(one_rss["roomid"])
        rssAP1Array.append(int(one_rss["meanRss"][0]))
        rssAP2Array.append(int(one_rss["meanRss"][1]))
    return roomIdArray, rssAP1Array, rssAP2Array



def create_udp_client(phone_ip):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    phone_address = (phone_ip, MY_PHONE_UDP_PORT)
    return sock, phone_address


def paused_too_long(ap_id):
    global last_seen
    curr_time = datetime.now()
    time_diff = curr_time - last_seen[ap_id]

    # update last_seen for next loop
    last_seen[ap_id] = curr_time

    if time_diff.seconds > LONGEST_WAITING_TIME_PER_PHONE:
        log.info(str(ap_id) + ' paused too long!')
        return True
    return False


def did_not_hear_too_long(ap_id):
    global last_seen
    curr_time = datetime.now()
    time_diff = curr_time - last_seen[ap_id]

    if time_diff.seconds > LONGEST_WAITING_TIME_PER_PHONE:
        num_of_pkts[ap_id] = 0
        dbm_sum[ap_id] = 0.0
        return True
    return False


def form_return_msg(first, second):
    return first + '$$$' + second


def lofi(udp_sock_for_phone, phone_address, db):
    global num_of_pkts, dbm_sum, w, TRAINING_START_FLAG, measure_start_time

    # grab all new pcap files
    log_files = glob.glob(TEMP_FILE_DIR)

    # sort these new files by time
    log_files.sort(key=lambda x: os.path.getmtime(x))

    # tempnow = datetime.now()
    # temp_diff0 = tempnow - last_seen[0]
    # temp_diff1 = tempnow - last_seen[1]
    # print '000...', temp_diff0.seconds, temp_diff0.microseconds, last_seen[0], num_of_pkts[0]
    # print '111...', temp_diff1.seconds, temp_diff1.microseconds, last_seen[1], num_of_pkts[1], '\n\n\n'
    did_not_hear_too_long(0)
    did_not_hear_too_long(1)

    # loop through them
    for pkt_idx, old_file in enumerate(log_files):
        output = subprocess.check_output("tshark -r %s -e radiotap.mactime -e radiotap.dbm_antsignal \
                                        -e frame.number -T fields -e ip.src -e ip.dst -e ip.id -e data" % old_file,
                                         shell=True, universal_newlines=True)
        # if this is a valid upd packet from a phone
        if len(output) > 0:
            # move this file to our log directory
            new_file = LOG_FILE_DIR + old_file[10:]
            subprocess.check_output("mv -f %s %s" % (old_file, new_file), shell=True)
            pkts = output.strip().split('\n')
            for pkt in pkts:
                fields = pkt.split('\t')
                items = {}
                id_str = ""
                room_id_str = ""
                pkt_type_id = ""
                which_ap = old_file.split('_')[0].split('/')[3]
                phone_ip = ""
                curr_dbm = [0.0, 0.0]
                for idx, field in enumerate(fields):
                    items[str(idx)] = field
                    if idx == 3:
                        # this is the phone ip address
                        phone_ip = field
                    if idx == 6:
                        # this is the UDP packet id
                        udp_id = field.split(UDP_DELIMITER)[0]
                        for i in xrange(0, len(udp_id), 2):
                            id_str += chr(int(udp_id[i:i + 2], 16))

                        room_id = field.split(UDP_DELIMITER)[1]
                        for i in xrange(0, len(room_id), 2):
                            room_id_str += chr(int(room_id[i:i + 2], 16))

                        type_id = field.split(UDP_DELIMITER)[2]
                        for i in xrange(0, len(type_id), 2):
                            pkt_type_id += chr(int(type_id[i:i + 2], 16))

                # insert into mongo db
                db.collection.insert(items)

                items[str(idx + 1)] = id_str
                items[str(idx + 2)] = which_ap
                items["bin_file"] = new_file

                ap_id = int(which_ap[-1])-1
                curr_dbm[ap_id] = float(items["1"])

                if curr_dbm[ap_id]:
                    if paused_too_long(ap_id):
                        # reset if a phone is not active for too long time
                        num_of_pkts[ap_id] = 1
                        dbm_sum[ap_id] = curr_dbm[ap_id]
                    else:
                        num_of_pkts[ap_id] += 1
                        dbm_sum[ap_id] = round(dbm_sum[ap_id] * (1.0 - w) + curr_dbm[ap_id] * w, 2)

                    if num_of_pkts[ap_id] > WARMUP_STEP_SIZE_IN_PKTS:
                        msg = 'Running....AP' + str(ap_id) + ' heard ' + phone_ip + ', id:' + id_str + ', avg dbm:' \
                              + str(dbm_sum) + ', curr: ' + str(curr_dbm) + ' ' + str(num_of_pkts) + '\n\n'

                        # save into log file
                        log.info(msg)

                        if pkt_type_id == TRAINING_PKT_TYPE:
                            # this is the training code
                            print "...........training........."
                            if not TRAINING_START_FLAG:
                                measure_start_time = datetime.now()
                                TRAINING_START_FLAG = True
                            else:
                                # training
                                time_diff = datetime.now() - measure_start_time
                                if time_diff.seconds > TRAINING_TIME:
                                    TRAINING_START_FLAG = False

                                    # save into database, i.e., update if existed, otherwise insert
                                    # db.metrics.update({'roomid':room_id_str}, {'$set': {'meanRss':dbm_sum}}, upsert=True)

                                    return_msg = form_return_msg(room_id_str, str(dbm_sum))

                                    # logging measured meanRSS
                                    log.info('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%')
                                    log.info('MeanRSS at Room ' + return_msg)
                                    log.info('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n\n')

                                    # feedback to phones
                                    sent = udp_sock_for_phone.sendto(return_msg, phone_address)

                                    # reset variables
                                    num_of_pkts = [0, 0]
                                    dbm_sum = [0.0, 0.0]
                                    reset_last_seen()
                        else:
                            # this is the code for the main view
                            # 1. use curr rss to match the rss in db
                            curr_loc = match_location(db)
                            # 2. feedback to phone
                            return_msg = form_return_msg(curr_loc, str(dbm_sum)+ ' ' + str(curr_dbm))
                            print return_msg
                            sent = udp_sock_for_phone.sendto(return_msg, phone_address)
                            # reset_last_seen()
                    else:
                        # do not use these pkts
                        warmup_msg = 'Warmup: AP' + str(ap_id)  + ': got ' + str(num_of_pkts) + ' pkts so far! ' + \
                                       str(dbm_sum) + ' ' + str(curr_dbm)
                        log.info(warmup_msg)

        # remove old file
        subprocess.check_output("rm -f %s" % old_file, shell=True)


def main():
    setup_logging()
    db = open_mongo()

    udp_sock_for_phone, phone_address = create_udp_client(MY_PHONE_IP)
    while True:
        measure_start_time = datetime.now()
        lofi(udp_sock_for_phone, phone_address, db)
        # print db.metrics.count()
        sleep(1)


if __name__ == "__main__":
    main()


