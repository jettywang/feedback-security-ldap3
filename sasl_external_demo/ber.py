"""Minimal BER/DER TLV codec used by the in-process LDAP protocol double.

Only the subset needed for SASL EXTERNAL bind, WhoAmI and search is implemented.
Real deployments parse with pyasn1 inside ldap3; this module exists so the
stand-in server can inspect/emit wire bytes without an external directory.
"""

INTEGER = 0x02
OCTET_STRING = 0x04
NULL = 0x05
ENUMERATED = 0x0A
SEQUENCE = 0x30

CLASS_UNIVERSAL = 0
CLASS_APPLICATION = 1
CLASS_CONTEXT = 2
CLASS_PRIVATE = 3


def length(n):
    if n < 0x80:
        return bytes([n])
    chunks = []
    while n:
        chunks.append(n & 0xFF)
        n >>= 8
    body = bytes(reversed(chunks))
    return bytes([0x80 | len(body)]) + body


def tlv(tag, content):
    if isinstance(tag, str):
        tag = tag.encode('utf-8')
    if isinstance(content, str):
        content = content.encode('utf-8')
    return bytes([tag]) + length(len(content)) + content


def seq(*parts):
    return tlv(SEQUENCE, b''.join(parts))


def integer(value):
    if value == 0:
        body = b'\x00'
    else:
        chunks = []
        n = value
        while n:
            chunks.append(n & 0xFF)
            n >>= 8
        body = bytes(reversed(chunks))
        if body[0] & 0x80:
            body = b'\x00' + body
    return tlv(INTEGER, body)


def enumerated(value):
    return tlv(ENUMERATED, integer(value)[2:])


def octet_string(value):
    if value is None:
        value = b''
    if isinstance(value, str):
        value = value.encode('utf-8')
    return tlv(OCTET_STRING, value)


def context_tag(number, content=b'', constructed=False, cls=CLASS_CONTEXT):
    tag = (cls << 6) | (0x20 if constructed else 0) | number
    return tlv(tag, content)


def application_tag(number, content, constructed=True):
    return context_tag(number, content, constructed=constructed, cls=CLASS_APPLICATION)


class Element:
    def __init__(self, cls, constructed, number, content, raw):
        self.cls = cls
        self.constructed = constructed
        self.number = number
        self.content = content
        self.raw = raw

    def children(self):
        out = []
        data = self.content
        while data:
            elem, data = parse_one(data)
            out.append(elem)
        return out

    def child(self, number):
        for c in self.children():
            if c.cls == CLASS_CONTEXT and c.number == number:
                return c
        return None

    def integer_value(self):
        return int.from_bytes(self.content, 'big', signed=True)

    def text(self):
        return self.content.decode('utf-8')

    def __repr__(self):
        kind = ('U', 'C', 'A', 'P')[self.cls]
        return '<Element %s%s constructed=%s len=%d>' % (kind, self.number, self.constructed, len(self.content))


def parse_one(data):
    if not data:
        raise ValueError('empty TLV')
    first = data[0]
    cls = first >> 6
    constructed = bool(first & 0x20)
    number = first & 0x1F
    idx = 1
    if number == 0x1F:  # high-tag-number form, not expected in LDAP
        number = 0
        while True:
            b = data[idx]
            idx += 1
            number = (number << 7) | (b & 0x7F)
            if not b & 0x80:
                break
    first_len = data[idx]
    idx += 1
    if first_len < 0x80:
        size = first_len
    else:
        nbytes = first_len & 0x7F
        size = int.from_bytes(data[idx:idx + nbytes], 'big')
        idx += nbytes
    content = data[idx:idx + size]
    if len(content) != size:
        raise ValueError('truncated TLV')
    return Element(cls, constructed, number, content, data[:idx + size]), data[idx + size:]


def parse_message(data):
    envelope, _ = parse_one(data)
    kids = envelope.children()
    message_id = kids[0].integer_value()
    protocol_op = kids[1]
    controls = kids[2] if len(kids) > 2 else None
    return message_id, protocol_op, controls


def frame(message_id, protocol_op_bytes, controls_bytes=b''):
    body = integer(message_id) + protocol_op_bytes + controls_bytes
    return seq(body)
