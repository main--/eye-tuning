import struct, gzip, sys
import pprint, json, plistlib, itertools
#from pydaap.pydaap import DaapParser
#from pydaap.pydaap.request import DaapStringIO
import daap
from itunes_proto import PBFusePreferences_pb2

f = open(sys.argv[1], 'rb')

def deser(fmt):
    return struct.unpack(fmt, f.read(struct.calcsize(fmt)))

conn_index = 0
class ConnInfo:
    def __init__(self, name):
        global conn_index
        self.index = conn_index
        conn_index += 1
        self.name = name
        self.din = []
        self.dout = []

fallback_id = 0xdead00
conns = {}

while True:
    t = f.read(1)
    if t == b'':
        break
    elif t == b'N':
        rid, = deser('<Q')
        name = b''
        while True:
            c = f.read(1)
            if c == b'\0':
                break
            name += c

        #try:
        #    backup = conns[rid]
        #except KeyError:
        #    pass
        #else:
        #    conns[fallback_id] = backup
        #    fallback_id += 1
        #conns[rid] = ConnInfo(name)
        try:
            _ = conns[rid]
        except KeyError:
            conns[rid] = ConnInfo(name)
    elif t == b'B':
        out, rid, length = deser('<?QI')
        buf = f.read(length)
        conn = conns[rid]
        if out:
            conn.dout.append(buf)
        else:
            conn.din.append(buf)
        #print((out, rid, length, buf))
    else:
        raise ValueError(t)

class HttpMessage:
    def __init__(self, x):
        #print(x)
        head, body = b''.join(x).split(b'\r\n' * 2, 1)
        shead = head.split(b'\r\n')
        #print(shead)
        try:
            self.status = shead[0].decode('ascii')
        except UnicodeDecodeError:
            self.status = 'HTTP/1.1 200 OK'
        self.headers = dict(map(lambda a: tuple(map(lambda b: b.lower(), a.decode('ascii').split(': ', 1))), shead[1:]))
        self.rheaders = dict(map(lambda a: tuple(map(lambda b: b, a.decode('ascii').split(': ', 1))), shead[1:]))

        if self.headers.get('transfer-encoding', None) == 'chunked':
            chunks = []
            while body:
                count, body = body.split(b'\r\n', 1)
                count = int(count, 16)
                chunks.append(body[:count])
                assert body[count:count+2] == b'\r\n'
                body = body[count+2:]
                if count == 0:
                    self.trailing_garbage = body
                    body = None
            body = b''.join(chunks)
            clen = len(body)
        else:
            if self.status.startswith('GET') or self.status.startswith('HTTP/1.1 204'):
                clen = 0
            #elif self.headers.get('connection', None) == 'close':
            #    clen = int(self.headers['content-length'])
            #    body = body[:clen]
            else:
                if not self.headers.get('content-length'):
                    assert self.headers.get('connection', None) != 'close'
                    clen = len(body)
                else:
                    clen = int(self.headers['content-length'])
            #clen = 0 if self.status[:3] == 'GET' else 
            #print(clen)
            self.trailing_garbage = body[clen:]
            body = body[:clen]

        if clen == 0:
            self.body = None
            return

        if self.headers.get('content-encoding', None) == 'gzip':
            body = gzip.decompress(body)
        self.raw_body = body
        content_type = self.headers.get('content-type', '')
        if content_type == 'application/x-protobuf':
            thing = PBFusePreferences_pb2.PBFusePreferences()
            thing.ParseFromString(body)
            body = thing
        elif content_type == 'application/x-dmap-tagged':
            body = daap.parse(body)#DaapParser.parse(DaapStringIO(body))
        elif content_type.startswith('application/json'):
            body = json.loads(body)
        elif content_type in ['application/x-apple-plist', 'text/x-xml-plist', 'text/xml; charset=utf-8']:
            try:
                body = plistlib.loads(body)
            except:
                pass
        self.body = body

    def display(self):
        msg = self
        print(msg.status)
        for k, v in msg.rheaders.items():
            print(k + ':', v)

        print()

        if isinstance(msg.body, dict) or isinstance(msg.body, list):
            #print(repr(msg.body))
            pprint.pprint(msg.body)
        else:
            try:
                print(msg.body.decode('utf8'))
            except:
                print(repr(msg.body)[:140])
        print()
        print()
        
def http_direction(buf):
    buf = b''.join(buf)
    while b'\r\n' in buf:
        msg = HttpMessage([buf])
        buf = msg.trailing_garbage
        yield msg

class HttpPair:
    def __init__(self, req, resp):
        self.req = req
        self.resp = resp

    def display(self):
        self.req.display()
        self.resp.display()

    def __repr__(self):
        return self.req.status
        
class HttpConnection:
    def __init__(self, conn):
        #msgs = []
        #buf_out = conn.dout
        #buf_in = conn.din
        #while buf_out: # and buf_in:
        #    req = HttpMessage(buf_out)
        #    resp = HttpMessage(buf_in)
        #    buf_out = req.trailing_garbage
        #    buf_in = resp.trailing_garbage
        #    msgs.append((req, resp))
        #print(buf_in[:140])
        #assert not buf_in
        msgin = list(http_direction(conn.din))
        msgout = list(http_direction(conn.dout))
        #print(msgout)
        #print(msgin)
        assert len(msgin) <= len(msgout)
        if len(msgin) < len(msgout):
            print('WHAT THE FUCK {} vs {}'.format(len(msgout), len(msgin)))
        self.msgs = list(map(lambda x: HttpPair(x[0], x[1]), zip(msgout, msgin)))

    def display(self):
        for pair in self.msgs:
            pair.display()
        
def print_lenient(x):
    full = b''.join(x).split(b'\r\n')
    for line in full:
        try:
            print(line.decode('ascii'))
        except:
            print(repr(line)[:140])
    print()
    print()

def print_http(x):
    HttpMessage(x).display()


#msg = HttpMessage(conns[0x279bfd83770].din)
#print(repr(conns[0x279bfd83770].din))
#print(repr(msg.body))
#sys.exit(0)

#reqs = itertools.chain(*map(lambda x: HttpConnection(x).msgs, conns.values()))
#reqs = dict(map(lambda x: (x[0], list(x[1])), itertools.groupby(itertools.chain(*map(lambda x: HttpConnection(x).msgs, conns.values())), lambda x: x[0].headers['host'])))

'''
#reqs = list(sorted((msg for conn in conns.values() for msg in HttpConnection(conn).msgs if msg.req.headers['host'] != 'init.itunes.apple.com'), key=lambda c: c.resp.headers['date']))
reqs = list(sorted((msg for conn in conns.values() for msg in HttpConnection(conn).msgs if msg.req.headers['host'] in ['genius-2.itunes.apple.com', 'genius-upload-2.itunes.apple.com', 'genius-download-2.itunes.apple.com']), key=lambda c: c.resp.headers['date']))
for req in reqs:
    req.display()
    #print(req.resp.headers['date'])
sys.exit(0)
'''
#'''



#'''
reqs = {}
for conn in conns.values():
    for msg in HttpConnection(conn).msgs:
        k = msg.req.headers['host']
        try:
            l = reqs[k]
        except KeyError:
            l = []
            reqs[k] = l
        l.append(msg)
sys.exit(0)
'''
#'''


for (rid, conn) in sorted(conns.items(), key=lambda c: c[1].index):
    print('Connection 0x{:08x}:'.format(rid))
    HttpConnection(conn).display()
    #print(conn.dout)
    #print(conn.din)
    
    #print_http(conn.dout)
    #print_http(conn.din)
    print()
    print()
    print()
