import argparse
import asyncio
import base64
import binascii
import datetime
import email.utils
import hashlib
import hmac
import itertools
import json
import os
import pprint
import sys
import urllib.parse
import urllib.request
import urllib.error
import requests
import aiohttp
from aiohttp import websocket
import pyaudio
import speex


from flask import Flask, request

app = Flask(__name__)



WS_KEY = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def extractMeaning(msg):
    result = msg['nlu_interpretation_results']['payload']['interpretations'][0]  # get interpretation

    if (result['action']['intent']['value'] == 'Search'):
        cuisine = result['concepts']['food'][0]['value']
        return cuisine
    else:
        return ''

def getTripAdvisorRec(cuisine):
    preLoc = 'http://api.tripadvisor.com/api/partner/2.0/map/'

    lat = '45.5042' + ','
    #+ ','

    longitude = '-73.5747'
    # get from web

    postLoc = '/restaurants/?key=0E6BCC2424F74C14AF7F3E88CC983CE6&cuisines=' 
    print (cuisine)
    # cuisine = get from nuance

    requestURL = preLoc + lat + longitude + postLoc + cuisine

    print (requestURL)

    request = urllib.request.Request(requestURL)

    try:
        response = urllib.request.urlopen(request)
        tripAdvisor_data = response.read()
        d = json.loads(tripAdvisor_data.decode('utf-8'))
        #print (d)
        #pprint.pprint(d)
        address = d["data"][0]['address_obj']['address_string']
        name = d["data"][0]['name']

        output = "You should try " +  name + ".  It's located at " + address + "."
        print (output)

        data = {"text": output, "role": "appMaker"}
        
        headers = {'content-type': "application/json", "authorization": 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IjU2Yzk5YTY4YmQ1ZWRjMjkwMDY5YzQ0NCJ9.eyJzY29wZSI6ImFwcCIsImlhdCI6MTQ1NjA1Mjk4NH0.koZJ_ZmOxaUpnMsGg-ISxoAFRLjJYPV0nHWFgbx2-v4'}
        r = requests.post("https://api.smooch.io/v1/appusers/f23c633500dd30c939640888/conversation/messages", headers=headers , json=data)
        
        return output

    except (urllib.error.URLError):
        print ('An error occured.')



class WebsocketConnection:

    MSG_JSON = 1
    MSG_AUDIO = 2

    def __init__(self, url):
        self.url = url
        self.connection = None
        self.stream = None
        self.writer = None
        self.response = None

    @asyncio.coroutine
    def connect(self, app_id, app_key, use_plaintext=True):
        date = datetime.datetime.utcnow()
        sec_key = base64.b64encode(os.urandom(16))

        if use_plaintext:
            params = {
                'app_id': app_id,
                'algorithm': 'key',
                'app_key': binascii.hexlify(app_key),
            }
        else:
            datestr = date.replace(microsecond=0).isoformat()
            params = {
                'date': datestr,
                'app_id': app_id,
                'algorithm': 'HMAC-SHA-256',
                'signature': self.sign_credentials(datestr, app_key, app_id),
            }

        response = yield from aiohttp.request(
            'get', self.url + '?' + urllib.parse.urlencode(params),
            headers={
                'UPGRADE': 'WebSocket',
                'CONNECTION': 'Upgrade',
                'SEC-WEBSOCKET-VERSION': '13',
                'SEC-WEBSOCKET-KEY': sec_key.decode(),
            })

        if response.status == 401 and not use_plaintext:
            if 'Date' in response.headers:
                server_date = email.utils.parsedate_to_datetime(response.headers['Date'])
                if server_date.tzinfo is not None:
                    server_date = (server_date - server_date.utcoffset()).replace(tzinfo=None)
            else:
                server_date = yield from response.read()
                server_date = datetime.datetime.strptime(server_date[:19].decode('ascii'), "%Y-%m-%dT%H:%M:%S")

            # Use delta on future requests
            date_delta = server_date - date

            print("Retrying authorization (delta=%s)" % date_delta)

            datestr = (date + date_delta).replace(microsecond=0).isoformat()
            params = {
                'date': datestr,
                'algorithm': 'HMAC-SHA-256',
                'app_id': app_id,
                'signature': self.sign_credentials(datestr, app_key, app_id),
            }

            response = yield from aiohttp.request(
                'get', self.url + '?' + urllib.parse.urlencode(params),
                headers={
                    'UPGRADE': 'WebSocket',
                    'CONNECTION': 'Upgrade',
                    'SEC-WEBSOCKET-VERSION': '13',
                    'SEC-WEBSOCKET-KEY': sec_key.decode(),
                })

        if response.status != 101:
            info = "%s %s\n" % (response.status, response.reason)
            for (k, v) in response.headers.items():
                info += '%s: %s\n' % (k, v)
            info += '\n%s' % (yield from response.read()).decode('utf-8')

            if response.status == 401:
                raise RuntimeError("Authorization failure:\n%s" % info)
            elif response.status >= 500 and response.status < 600:
                raise RuntimeError("Server error:\n%s" %  info)
            elif response.headers.get('upgrade', '').lower() != 'websocket':
                raise ValueError("Handshake error - Invalid upgrade header")
            elif response.headers.get('connection', '').lower() != 'upgrade':
                raise ValueError("Handshake error - Invalid connection header")
            else:
                raise ValueError("Handshake error: Invalid response status:\n%s" % info)

        key = response.headers.get('sec-websocket-accept', '').encode()
        match = base64.b64encode(hashlib.sha1(sec_key + WS_KEY).digest())
        if key != match:
            raise ValueError("Handshake error - Invalid challenge response")

        # Switch to websocket protocol
        self.connection = response.connection
        self.stream = self.connection.reader.set_parser(websocket.WebSocketParser)
        self.writer = websocket.WebSocketWriter(self.connection.writer)
        self.response = response

    @asyncio.coroutine
    def receive(self):
        wsmsg = yield from self.stream.read()
        if wsmsg.tp == 1:
            return (self.MSG_JSON, json.loads(wsmsg.data))
        else:
            return (self.MSG_AUDIO, wsmsg.data)

    def send_message(self, msg):
        #log(msg, sending=True)
        self.writer.send(json.dumps(msg))

    def send_audio(self, audio):
        self.writer.send(audio, binary=True)

    def close(self):
        self.writer.close()
        self.response.close()
        self.connection.close()

    @staticmethod
    def sign_credentials(datestr, app_key, app_id):
        value = datestr.encode('ascii') + b' ' + app_id.encode('utf-8')
        return hmac.new(app_key, value, hashlib.sha256).hexdigest()


# def log(obj, sending=False):
#     print('>>>>' if sending else '<<<<')
#     print('%s' % datetime.datetime.now())
#     pprint.pprint(obj)
#     print()

@asyncio.coroutine
def understand_text(loop, url, app_id, app_key, context_tag, text_to_understand, use_speex=None):
    
    if use_speex is True and speex is None:
        print('ERROR: Speex encoding specified but python-speex module unavailable')
        return

    if use_speex is not False and speex is not None:
        audio_type = 'audio/x-speex;mode=wb'
    else:
        audio_type = 'audio/L16;rate=16000'

    client = WebsocketConnection(url)
    yield from client.connect(app_id, app_key)

    client.send_message({
        'message': 'connect',
        'device_id': '55555500000000000000000000000000',
        'codec': audio_type
    })

    tp, msg = yield from client.receive()
   # log(msg)  # Should be a connected message

    client.send_message({
        'message': 'query_begin',
        'transaction_id': 123,

        'command': 'NDSP_APP_CMD',
        'language': 'eng-USA',
        'context_tag': context_tag,
    })

    client.send_message({
        'message': 'query_parameter',
        'transaction_id': 123,

        'parameter_name': 'REQUEST_INFO',
        'parameter_type': 'dictionary',

        'dictionary': {
            'application_data': {
                'text_input': text_to_understand,
            }
        }
    })

    client.send_message({
        'message': 'query_end',
        'transaction_id': 123,
    })

    while True:
        tp, msg = yield from client.receive()
        #log(msg)

        if msg['message'] == 'query_end':
            break
        else:
            getTripAdvisorRec(extractMeaning(msg))

    client.close()


def nuanceParse(text):
    """
    For CLI usage:

        python nlu.py --help

    For audio + NLU:

        python nlu.py audio
        # 1. Start recording when prompted;
        # 2. Press <enter> when done.

    For text + NLU:

        python nlu.py text 'This is the sentence you want to test'

    """

    loop = asyncio.get_event_loop()
    #loop = IOLoop.instance()

    #text = hello()

    loop.run_until_complete(understand_text(
        loop,
        "https://httpapi.labs.nuance.com/v1",
        "NMDPTRIAL_kayla_branson_mail_mcgill_ca20160220161941",
        binascii.unhexlify("ce913fd9c15e7b03a453e3a928b8319719c47a57f94de4a2118fc1cd6091122e225108e3af83e653d6c9fcfe822e969bf210f2eb5ed68d6f664f3dc6e04ff402"),
        context_tag="M1726_A920",
        text_to_understand=text))


# if __name__ == '__main__':
#     main()

@app.route('/smooch', methods=['POST'])
def hello():
    data = request.get_json()
    message = data.get('messages')[0]['text']
    userId = data.get('appUser')['_id']
    print ("in hello")
    #nuanceParse(message)
    print (nuanceParse(message))
    return 'all good'

from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop

if __name__ == '__main__':
    http_server = HTTPServer(WSGIContainer(app))
    http_server.listen(5000)
    IOLoop.instance().start()




