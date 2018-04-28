#!/usr/bin/env python

from scapy.all import *
from daemon.runner import DaemonRunner
import os
import logging
import pyaudio
import wave
import requests

LOGLEVEL='DEBUG'

cwd = os.getcwd()

def get_ifttt_webhook_key():
    keyfile = open(os.path.join(cwd, 'ifttt_webhook_key.txt'))
    key = keyfile.readline()
    key = key.replace("\n","")
    keyfile.close()
    return key

ifttt_webhook_endpoint = 'https://maker.ifttt.com/trigger'
ifttt_webhook_key = get_ifttt_webhook_key()

class IftttWebHook:
    def __init__(self, webhook_endpoint, webhook_key, event_name, options={}):
        self.webhook_endpoint = webhook_endpoint
        self.webhook_key = webhook_key
        self.event_name = event_name
        self.options = options

    def send_event(self, options = {}):
        logging.debug('in %s', self.__class__.__name__)
        webhook_endpoint = "%s/%s/with/key/%s" % (
                self.webhook_endpoint,
                self.event_name,
                self.webhook_key)

        if options:
            r = requests.post(webhook_endpoint, data = options)
        else:
            logging.info(webhook_endpoint)
            r = requests.post(webhook_endpoint)

class DoorBell(object):
    CHUNK = 1024
    soundfile = os.path.join(cwd, 'lib/sounds/bingbong.wav')

    def chime(self):
        logging.debug('in %s', self.__class__.__name__)
        wf = wave.open(self.soundfile, 'rb')
        p = pyaudio.PyAudio()
        stream = p.open(format=p.get_format_from_width(wf.getsampwidth()),
                channels=wf.getnchannels(),
                rate=wf.getframerate(),
                output=True)

        data = wf.readframes(self.CHUNK)

        while data != '':
            stream.write(data)
            data = wf.readframes(self.CHUNK)

        stream.stop_stream()
        stream.close()
        wf.close()
        p.terminate()

class ButtonEvent(object):
    stdin_path = '/dev/null'
    stdout_path = os.path.join(cwd, 'button_event.log')
    stderr_path = os.path.join(cwd, 'button_event.err')
    pidfile_path = '/tmp/sniff_buttons.pid'
    pidfile_timeout = 5
    buttons = [{ 'name': 'regina', 'hwsrc': 'fc:65:de:d5:90:db' }]
    doorbell = DoorBell()
    webhook = IftttWebHook(ifttt_webhook_endpoint,ifttt_webhook_key,'button_pressed')

    def get_button_pressed(self, hwsrc):
        logging.debug('in %s', self.__class__.__name__)
        logging.debug("Processing %s" % hwsrc)
        for button in self.buttons:
            if hwsrc in button['hwsrc']:
                logging.info('%s button pressed' % button['name'])
                self.webhook.send_event(options={'value1': button['name']})
                self.doorbell.chime()

    def get_arp_src(self, packet):
        logging.debug('in %s', self.__class__.__name__)
        hwsrc = packet[ARP].hwsrc
        self.get_button_pressed(hwsrc)

    def run(self):
        logging.basicConfig(filename=self.stdout_path, level=LOGLEVEL)
        logging.info("Starting")
        sniff(filter='arp',iface='en0',prn=self.get_arp_src)

if __name__ == '__main__':
    # buttonEvent = ButtonEvent()
    # buttonEvent.run()
    buttonEventLoop = DaemonRunner(ButtonEvent())
    buttonEventLoop.do_action()
