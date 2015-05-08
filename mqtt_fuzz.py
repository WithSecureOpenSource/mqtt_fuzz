#! /usr/bin/python
# pylint: disable=line-too-long,no-member

# Copyright 2015 F-Secure Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You
# may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

"""mqtt_fuzz.py

Performs MQTT sessions as a client with a fuzzed PDU once in a while.
"""

from __future__ import division
from twisted.internet.protocol import Protocol, ClientFactory
import itertools
import time
import binascii
import fuzzpool
import random
import uuid
import calendar
import argparse
import os


class MQTTFuzzProtocol(Protocol):
    '''Implementation of a pseudo-MQTT protocol that conducts predefined MQTT
    sessions by replaying a series of stored MQTT control packets.'''

    def dataReceived(self, data):
        """Callback. If we receive data from the remote peer, print it out

        :param data: Data received from remote peer

        """
        print "%s:%s:Server -> Fuzzer: %s" % (calendar.timegm(time.gmtime()), self.session_id, binascii.b2a_base64(data))

    def connectionMade(self):
        """Callback. We have connected to the MQTT server, so start banging away

        """
        print "%s:%s:Connected to server" % (calendar.timegm(time.gmtime()), self.session_id)
        self.send_next_pdu()

    def send_next_pdu(self):
        """Send a PDU and schedule the next PDU

        """
        from twisted.internet import reactor

        try:
            self.send_pdu(self.current_session.next())
            reactor.callLater(self.send_delay / 1000, self.send_next_pdu)
        except StopIteration:
            # We have sent all the PDUs of this session. Tear down
            # connection. It will trigger a reconnection in the factory.
            print "%s:%s:End of session, initiating disconnect." % (calendar.timegm(time.gmtime()), self.session_id)
            self.transport.loseConnection()

    def send_pdu(self, pdutype):
        """Send either a valid case or a fuzz case

        :param pdutype: Message type (Directory from which the message will be sent)

        """
        from twisted.internet import reactor

        try:
            # 1 in 10, send a fuzz case, otherwise a valid case
            if random.randint(1, 10) < self.fuzz_ratio:
                print "%s:%s:Sending fuzzed %s" % (calendar.timegm(time.gmtime()), self.session_id, pdutype)
                data = self.fuzzdata.get_next_fuzzcase(os.path.join(self.validcases_path, pdutype))
            else:
                print "%s:%s:Sending valid %s" % (calendar.timegm(time.gmtime()), self.session_id, pdutype)
                data = self.fuzzdata.get_valid_case(os.path.join(self.validcases_path, pdutype))
            print "%s:%s:Fuzzer -> Server: %s" % (calendar.timegm(time.gmtime()), self.session_id, binascii.b2a_base64(data).rstrip())
            self.transport.write(data)
        except (IOError, OSError) as err:
            print "Could not run the fuzzer. Check -validcases and -radamsa options. The error was: %s" % err
            reactor.stop()

class MQTTClientFactory(ClientFactory):
    '''Factory that creates pseudo-MQTT clients'''

    protocol = MQTTFuzzProtocol

    # These are the sessions that we will be running through.
    # If you want to extend the fuzzer with new control packets,
    # copy some raw valid control packets into a directory under valid-cases
    # and refer to that directory by name in one of these sessions here.
    # See readme.txt.
    session_structures = [
        ['connect', 'disconnect'],
        ['connect', 'subscribe', 'disconnect'],
        ['connect', 'subscribe', 'publish', 'disconnect'],
        ['connect', 'subscribe', 'publish', 'publish-ack', 'publish-release', 'publish-complete', 'publish-received', 'publish-complete', 'disconnect'],
        ['connect', 'publish', 'publish-release', 'subscribe', 'publish-received', 'publish-ack', 'disconnect']]

    def __init__(self, fuzz_ratio, send_delay, radamsa_path, validcases_path):
        # We cycle through the sessions again and again
        self.session = itertools.cycle(iter(self.session_structures))

        # Copy the data into this instance so we can use it later
        self.fuzzdata = fuzzpool.FuzzPool(radamsa_path)
        self.fuzz_ratio = fuzz_ratio
        self.send_delay = send_delay
        self.validcases_path = validcases_path

    def buildProtocol(self, address):
        # Create the fuzzer instance
        protocol_instance = ClientFactory.buildProtocol(self, address)

        # Tell the fuzzer instance which type of session it should run
        protocol_instance.current_session = iter(self.session.next())
        protocol_instance.fuzzdata = self.fuzzdata
        protocol_instance.session_id = str(uuid.uuid4())
        protocol_instance.fuzz_ratio = self.fuzz_ratio
        protocol_instance.send_delay = self.send_delay
        protocol_instance.validcases_path = self.validcases_path
        return protocol_instance

    def clientConnectionFailed(self, connector, reason):
        # Callback: The server under test has died
        from twisted.internet import reactor

        print "%s:Failed to connect to MQTT server: %s" % (calendar.timegm(time.gmtime()), reason)
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        # Callback: The server under test closed connection or we decided to
        # tear down the connection at the end of a session. We'll
        # reconnect (which starts another session in the protocol
        # instance)
        print "%s:Connection to MQTT server lost: %s" % (calendar.timegm(time.gmtime()), reason)
        print "%s:Reconnecting" % calendar.timegm(time.gmtime())
        connector.connect()

def run_tests(host, port, ratio, delay, radamsa, validcases):  # pylint: disable=R0913
    '''Main function to run'''
    from twisted.internet import reactor

    factory = MQTTClientFactory(ratio, delay, radamsa, validcases)
    hostname = host
    port = int(port)
    print "%s:Starting fuzz run to %s:%s" % (calendar.timegm(time.gmtime()), hostname, port)
    reactor.connectTCP(hostname, port, factory)
    reactor.run()
    print "%s:Stopped fuzz run to %s:%s" % (calendar.timegm(time.gmtime()), hostname, port)

# The following is the entry point from command line
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MQTT-fuzz, a simple MQTT protocol fuzzer.')
    parser.add_argument('host', metavar='target_host',
                        type=str,
                        default='localhost',
                        help='Host name of MQTT server / broker under test')
    parser.add_argument('port', metavar='target_port',
                        type=int,
                        default=1883,
                        help='Port number of MQTT server / broker under test')
    parser.add_argument('-ratio', metavar='fuzz_ratio',
                        type=int, required=False, choices=range(0, 11),
                        default=3, help='How many control packets should be fuzzed per 10 packets sent (0 = fuzz nothing, 10 = fuzz all packets, default is 3)')
    parser.add_argument('-delay', metavar='send_delay',
                        type=int, required=False,
                        default=50, help='How many milliseconds to wait between control packets sent, default is 50 ms')
    parser.add_argument('-validcases', metavar='validcase_path',
                        type=str, required=False,
                        default='valid-cases/', help='Path to the valid-case directories, default is "valid-cases/"')
    parser.add_argument('-fuzzer', metavar='fuzzer_path', type=str,
                        default='radamsa', required=False,
                        help='Path and name of the Radamsa binary, default "radamsa"')
    args = parser.parse_args()
    run_tests(args.host, args.port, args.ratio, args.delay, args.fuzzer, args.validcases)
