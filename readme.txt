mqtt_fuzz
=========

This is a simple fuzzer for the MQTT (http://mqtt.org) protocol. It
does not try to implement any fancy protocol processing; instead, it
plays back recorded MQTT control packets, and once in a while, sends a
fuzzed control packet.

Requirements
------------

You need to obtain and compile Radamsa
(https://github.com/aoh/radamsa). Fuzz cases are generated using
Radamsa. The tool has been tested with version 0.4a. Earlier versions
may have different command line parameters and thus may not work.

You need to install Python Twisted. Do this either through pip or from
https://twistedmatrix.com/trac/wiki/Downloads.

Usage
-----

DO NOT RUN THE TOOL AGAINST A TARGET THAT YOU DO NOT HAVE AN
AUTHORIZATION TO TEST.

Choose which MQTT server (broker) you want to test. You might want to
consider linking it with address sanitizer (ASan, e.g.,
-fsanitize=address). ASan helps to ensure that the target truly
crashes if the fuzz cases cause corruption.

It is suggested that you run the target under the debugger so when it
crashes, you get a stack trace. You can also run the GDB 'exploitable'
command (https://github.com/jfoote/exploitable) to quickly determine
how worried you need to be.

Run the tool. For command line options, run

  python mqtt_fuzz.py --help

The tool sends a series of pre-defined sequences of MQTT control
packets. You can change these sequences, and extend the control packet
support (see 'Extending mqtt_fuzz', below).

The ratio of valid:fuzzed control packets controls how quickly the
fuzz cases are being sent. Sending too many fuzzed packets may
decrease the test effectiveness - for example, if all your CONNECT
packets are always fuzzed, you might not ever get to tickle the
server's state machine beyond the CONNECT.

The tool will run until the server stops responding to new
connections.

Each control packet sequence ('session') will have a unique UUID tag
and all messages will be timestamped on the output. Ensure that the
target and fuzzer hosts' clocks are synchronised, and you can find the
messages that caused problems using the timestamp. The process is as
follows:

1) Detect a crash and get a UNIX epoch timestamp of the crash (shown
   in gdb by default).
2) Select all the lines from the fuzzer's output log that have that
   timestamp.
3) Determine all the session UUIDs that are listed on those lines.
4) Extract all the lines from the fuzzer's output log that have one of
   these UUIDs (those sessions may start or end before and after the
   timestamp).
5) Now you have all the control messages that were sent, and their
   ordering.

If you run the fuzzer in test automation, you would likely want to
automate this analysis step.

The control messages that are sent are output to the log using base64
encoding. The wire protocol of MQTT is binary; base64 is used here
just to enable easier copy-pasting of the control messages in a format
that is less likely to cause problems.

Once you have found a sequence of control messages that caused the
crash, you can extract all the control messages from the log and put
them into reprotool.py. This tool will send those messages to the
host. Edit the number and order of the messages so that you can
reproduce the crash running reprotool.py. Once you have the minimal
set that triggers the crash, you have a suitable PoC for the MQTT
server developers.

Extending mqtt_fuzz
-------------------

MQTT tests MQTT servers by acting as a client.

The default installation currently has the following control packets [*]:

CONNECT
CONNACK
PUBLISH
PUBACK
SUBSCRIBE
PUBCOMP
PUBREL
PUBREC
DISCONNECT

Specifically, the following control packets are missing:

UNSUBSCRIBE
UNSUBACK
PINGREQ
PINGRESP
SUBACK

Some of the missing packets are server-to-client packets, so in theory
shouldn't be in scope. However, for fuzzing, they should be fair game
and should be sent to the server during testing.

Your application might also process data on higher protocol layers
(that is, data that is published and subscribed to using MQTT). That
code would usually benefit from fuzz testing, too. Although it would
be preferable to use valid MQTT and just fuzz the higher-level
protocol, mqtt_fuzz can be used here by adding new control packets
that carry the higher-level protocol data. You are likely to require
longer fuzz test runs.

You can add new control packets simply by creating a new directory
(with an arbitrary name) under mqtt_fuzz/valid-cases, and putting
examples of valid control packets in that directory. You can obtain
those examples, for example, by sniffing traffic with Wireshark (>
1.12.0) and by extracting the raw MQTT protocol layer data into files
in that directory. In addition, you need to add a new session in the
session_structures list that actually uses that control packet.

As an example, assume you want to add a new control packet where you
have your own payload within the PUBLISH message, and you want to fuzz
these kind of messages. You could create a directory
valid-cases/publish-with-payload, copy raw example valid cases into
this directory (minimum of one, optimally around 15), and then add the
following list in the session_structures:

['connect', 'publish-with-payload', 'disconnect']

Now you have a new control packet added. Fuzz case generation will be
automatic.

Legal
-----

See LICENCE.

Contact: opensource@f-secure.com.
Original tool author: Antti Vähä-Sipilä.

[*] The control packet examples in the tool's valid case directories
have been sniffed with Wireshark from traffic that was generated by
Eclipse Paho MQTT interoperability testing tool (client_test.py) at
https://git.eclipse.org/c/paho/org.eclipse.paho.mqtt.testing.git/.  To
clarify, the valid cases only constitute of output whose syntax is
governed by the MQTT protocol specification, and do not include any
code from the tool itself. If you have further MQTT control packet
examples that you'd like to contribute, please send a pull request.
