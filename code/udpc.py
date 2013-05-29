# __author__ = 'skyahead'
#
# from socket import *
# import sys
# import select
# address = ('localhost', 55555)
# server_socket = socket(AF_INET, SOCK_DGRAM)
# server_socket.bind(address)
#
# while True:
#     print "Listening"
#     recv_data, addr = server_socket.recvfrom(2048)
#     print recv_data
#     if recv_data == "Request 1" :
#         print "Received request 1"
#         server_socket.sendto("Response 1", addr)
#     elif recv_data == "Request 2" :
#         print "Received request 2"
#         data = "Response 2"
#         server_socket.sendto(data, addr)

__author__ = 'skyahead'

import socket
import sys

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# server_address = ('10.220.10.114', 55555)
server_address = ('10.220.10.85', 55555)
message = 'This is the message.  It will be repeated.'

try:

    # Send data
    print >>sys.stderr, 'sending "%s"' % message
    sent = sock.sendto(message, server_address)

    # Receive response
    print >>sys.stderr, 'waiting to receive'
    data, server = sock.recvfrom(4096)
    print >>sys.stderr, 'received "%s"' % data

finally:
    print >>sys.stderr, 'closing socket'
    sock.close()

