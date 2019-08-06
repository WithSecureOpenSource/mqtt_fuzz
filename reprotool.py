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

# reprotool.py
#
# Plays back an MQTT session to reproduce issues.

from twisted.internet.protocol import Protocol, ClientFactory
import time
import binascii
import uuid
import calendar

class MQTTFuzzProtocol(Protocol):
    '''Plays back a specified MQTT session.'''

    # Raw MQTT messages to be played back, in base64.
    # This just connects and disconnects. Replace
    # this data with a list of data from the fuzzer logs.
    session_data = ['EBYABE1RVFQEAAAAAApteWNsaWVudGlk',
                    '4AA=']

    current_session = iter(session_data)

    def dataReceived(self, data):
        """Callback: If we receive data from the remote peer, print it out

        :param data: Data received from remote peer

        """
        print("%s:%s:Server -> Fuzzer: %s".format(calendar.timegm(time.gmtime()), self.session_id, binascii.b2a_base64(data)))

    def connectionMade(self):
        """Callback: We have connected to the MQTT server, so start banging away.

        """
        print("%s:%s:Connected to server".format(calendar.timegm(time.gmtime()), self.session_id))
        self.send_next_pdu()

    def send_next_pdu(self):
        """Send the next message in list

        """
        from twisted.internet import reactor

        try:
            # Send a PDU and schedule the next PDU
            self.send_pdu(next(self.current_session))
            reactor.callLater(0.05, self.send_next_pdu)
        except StopIteration:
            # We have sent all the PDUs of this session. Tear down
            # connection. It will trigger a reconnection in the factory.
            print("%s:%s:End of session, initiating disconnect.".format(calendar.timegm(time.gmtime()), self.session_id))
            self.transport.loseConnection()

    def send_pdu(self, pdu):
        """Actually send the message out

        :param pdu: The message to be sent out
        """
        # Send either a valid case or a fuzz case
        # 1 in 10, send a fuzz case, otherwise a valid case
        print("%s:%s:Fuzzer -> Server: %s".format(calendar.timegm(time.gmtime()), self.session_id, pdu))
        self.transport.write(binascii.a2b_base64(pdu))

class MQTTClientFactory(ClientFactory):

    protocol = MQTTFuzzProtocol  # Factory creates Fuzzer clients

    def buildProtocol(self, address):
        # Create the fuzzer instance
        protocol_instance = ClientFactory.buildProtocol(self, address)
        # Tell the fuzzer instance which type of session it should run
        protocol_instance.session_id = str(uuid.uuid4())
        return protocol_instance

    def clientConnectionFailed(self, connector, reason):
        # The server under test has died
        from twisted.internet import reactor

        print("%s:Failed to connect to MQTT server: %s".format(calendar.timegm(time.gmtime()), reason))
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        # The server under test closed connection or we decided to
        # tear down the connection at the end of a session. We'll
        # reconnect (which starts another session in the protocol instance)
        from twisted.internet import reactor

        print("%s:Connection to MQTT server lost: %s".format(calendar.timegm(time.gmtime()), reason))
        reactor.stop()

def run_tests():
    """Main function, sends the predetermined list of messages

    """

    from twisted.internet import reactor
    factory = MQTTClientFactory()
    hostname = 'localhost'
    port = 1883
    print("%s:Starting repro run to %s:%s".format(calendar.timegm(time.gmtime()), hostname, port))
    reactor.connectTCP(hostname, port, factory)
    reactor.run()
    print("%s:Stopped repro run to %s:%s".format(calendar.timegm(time.gmtime()), hostname, port))

if __name__ == '__main__':
    run_tests()
