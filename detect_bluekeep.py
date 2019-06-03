#!/usr/bin/env python3

import argparse
import sys
import traceback
import struct
import socket
import hashlib
import string
import random
import logging
import os
import sys
import concurrent.futures
from binascii import unhexlify, hexlify
from ipaddress import IPv4Network

log = logging.getLogger("bluekeep")

STATUS_VULNERABLE = "Vulnerable"
STATUS_UNKNOWN = "Unknown"
STATUS_NORDP = "No RDP"
STATUS_SAFE = "Safe"

# https://github.com/DavidBuchanan314/rc4
class RC4:
    """
    This class implements the RC4 streaming cipher.

    Derived from http://cypherpunks.venona.com/archive/1994/09/msg00304.html
    """

    def __init__(self, key, streaming=True):
        assert(isinstance(key, (bytes, bytearray)))

        # key scheduling
        S = list(range(0x100))
        j = 0
        for i in range(0x100):
            j = (S[i] + key[i % len(key)] + j) & 0xff
            S[i], S[j] = S[j], S[i]
        self.S = S

        # in streaming mode, we retain the keystream state between crypt()
        # invocations
        if streaming:
            self.keystream = self._keystream_generator()
        else:
            self.keystream = None

    def crypt(self, data):
        """
        Encrypts/decrypts data (It's the same thing!)
        """
        assert(isinstance(data, (bytes, bytearray)))
        keystream = self.keystream or self._keystream_generator()
        return bytes([a ^ b for a, b in zip(data, keystream)])

    def _keystream_generator(self):
        """
        Generator that returns the bytes of keystream
        """
        S = self.S.copy()
        x = y = 0
        while True:
            x = (x + 1) & 0xff
            y = (S[x] + y) & 0xff
            S[x], S[y] = S[y], S[x]
            i = (S[x] + S[y]) & 0xff
            yield S[i]


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/db6713ee-1c0e-4064-a3b3-0fac30b4037b

def pdu_connection_request():
    pkt = (
        b"\x03\x00" + # TPKT header
        b"\x00\x2b" + # TPKT leangth
        # X.224 Connection Request
        b"\x26" + # length
        b"\xe0" + # CR CDT
        b"\x00\x00" + # DST-REF
        b"\x00\x00" + # SRC-REF
        b"\x00" + # CLASS OPTION = Class 0
        # Cookie: mstshash=IDENTIFIER
        b"\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d" +
        ''.join(random.choice(string.ascii_letters)
                   for i in range(5)).encode("ascii") + # "username"
        b"\x0d\x0a" +
        b"\x01" + # RDP_NEG_REQ
        b"\x00" + # flags
        b"\x08" + # length
        b"\x00\x00\x00\x00\x00" # PROTOCOL_RDP - standard security
    )
    return pkt


def rdp_connect(sock):
    ip, port = sock.getpeername()
    log.debug(f"[D] [{ip}] Verifying RDP protocol...")

    res = rdp_send_recv(sock, pdu_connection_request())
    # 0300 0013 0e d0 0000 1234 00
    # 03 - response type x03 TYPE_RDP_NEG_FAILURE x02 TYPE_RDP_NEG_RSP
    # 00 0800 05000000
    if res[0:2] == b'\x03\x00' and (res[5] & 0xf0) == 0xd0:
        if res[0xb] == 0x2:
            log.debug(f"[D] [{ip}] RDP connection accepted by the server.")
            return True
        elif res[0xb] == 0x3:
            log.debug(f"[D] [{ip}] RDP connection rejected by the server.")
            proto = res[0xf]
            prs = []
            if proto & 0x1:
                prs.append("PROTOCOL_SSL")
            if proto & 0x2:
                prs.append("PROTOCOL_HYBRID")
            if proto & 0x4:
                prs.append("PROTOCOL_RDSTLS")
            if proto & 0x8:
                prs.append("PROTOCOL_HYBRID_EX")
            log.debug(f"[D] [{ip}] RDP server demands protocols: {', '.join(prs)}")

            return False
    raise RdpCommunicationError()


def pdu_connect_initial():
    pkt = (
        #000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F
        "0300" +
        "01ca" +
        "02f080" +
        "7f65" + # BER - Connect Initial
        "8201be" + # Length
        "040101" + #
        "040101" + #
        "0101ff" + # upwardFlag = TRUE
        "3020" +
        "02020022" +
        "02020002" +
        "02020000" +
        "02020001" +
        "02020000" +
        "02020001" +
        "0202ffff" +
        "02020002" +
        "3020" +
        "02020001" +
        "02020001" +
        "02020001" +
        "02020001" +
        "02020000" +
        "02020001" +
        "02020420" +
        "02020002" +
        "3020" +
        "0202ffff" +
        "0202fc17" +
        "0202ffff" +
        "02020001" +
        "02020000" +
        "02020001" +
        "0202ffff" +
        "02020002" +
        "0482014b" + # userData 0x4b length
        "000500147c00018142000800100001c00044756361" +
        "8134" +
        "01c0d800" + #CS_CORE - length 0xd8
        "04000800" +
        "2003" +
        "5802" +
        "01ca" +
        "03aa" +
        "09040000" +
        "280a0000" # client build
    )
        #000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F
    pkt += (
        "7800310038003100300000000000000000000000000000000000000000000000" + # clientName
        "04000000" + # keyboardType
        "00000000" + # keyboardSubType
        "0c000000" + # keyboardFunctionKey
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "01ca" + # postBeta2ColorDepth
        "0100" + # clientProductId
        "00000000" +
        "1800" + # highColorDepth
        "0700" + # supportedColorDepths
        "0100" + 
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "00" +
        "00" +
        "00000000" +
        "04c00c00" + # CS_CLUSTER
        "09000000" + # CLUSTER flags
        "00000000" +
        "02c00c00" + # CS_SECURITY
        "03000000" + # encryptionMethods
        "00000000" + 
        "03c04400" + # CS_NET
        "05000000" + # Channel count
        "636c697072647200" + # cliprdr
        "c0a00000" +
        "4d535f5431323000" + # MS_T120
        "80800000" +
        "726470736e640000" + # rdpsnd
        "c0000000" +
        "736e646462670000" + # snddbg
        "c0000000" +
        "7264706472000000" + # rdpdr
        "80800000")
    return unhexlify(pkt)

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/04c60697-0d9a-4afd-a0cd-2cc133151a9c


def pdu_erect_domain_request():
    pkt = (
        b"\x03\x00" +  # header
        b"\x00\x0c" +  # length
        # X.224 Data TPDU (2 bytes: 0xf0 = Data TPDU, 0x80 = EOT, end of transmission)
        b"\x02\xf0\x80" +
        # T.125 MCS Erect Domain (PER encoding)
        b"\x04\x00\x01\x00\x01")
    return pkt

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f5d6a541-9b36-4100-b78f-18710f39f247


def pdu_attach_user_request():
    pkt = (
        b"\x03\x00" +  # header
        b"\x00\x08" +  # length
        # X.224 Data TPDU (2 bytes: 0xf0 = Data TPDU, 0x80 = EOT, end of transmission)
        b"\x02\xf0\x80" +
        b"\x28"     # PER encoded PDU contents
    )
    return pkt

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/64564639-3b2d-4d2c-ae77-1105b4cc011b


def pdu_channel_request(user1, channel_id):
    log.debug(f"Channel request '{user1}' '{channel_id}'")
    pkt = (
        b"\x03\x00" +  # header
        b"\x00\x0c" +  # length
        b"\x02\xf0\x80" +  # X.224
        b"\x38" +  # ChannelJoin request
        # network byteorder
        struct.pack('>HH', user1, channel_id)
    )
    return pkt

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9cde84cd-5055-475a-ac8b-704db419b66f


def pdu_security_exchange(rcran, rsexp, rsmod, bitlen):
    log.debug(f"Encrypting")
    encrypted_rcran_bignum = rsa_encrypt(rcran, rsexp, rsmod)
    log.debug(f"Encrypted")
    encrypted_rcran = int_to_bytestring(encrypted_rcran_bignum)

    bitlen += 8
    bitlen_hex = struct.pack("<L", bitlen)

    log.debug(f"Encrypted client random: #{hexlify(encrypted_rcran)}")

    userdata_length = 8 + bitlen
    userdata_length_low = userdata_length & 0xFF
    userdata_length_high = userdata_length >> 8
    flags = 0x80 | userdata_length_high

    pkt = b"\x03\x00"
    pkt += struct.pack(">H", userdata_length+15)  # TPKT
    pkt += b"\x02\xf0\x80"  # X.224
    pkt += b"\x64"  # sendDataRequest
    pkt += b"\x00\x08"  # intiator userId
    pkt += b"\x03\xeb"  # channelId = 1003
    pkt += b"\x70"  # dataPriority
    pkt += struct.pack("B", flags)
    pkt += struct.pack("B", userdata_length_low)  # UserData length
    pkt += b"\x01\x00"  # securityHeader flags
    pkt += b"\x00\x00"  # securityHeader flagsHi
    pkt += bitlen_hex  # securityPkt length
    pkt += encrypted_rcran  # 64 bytes encrypted client random
    # 8 bytes rear padding (always present)
    pkt += b"\x00\x00\x00\x00\x00\x00\x00\x00"
    return pkt


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/772d618e-b7d6-4cd0-b735-fa08af558f9d
def pdu_client_info():
    pkt = (
        "000000003301000000000a000000000000000000" +
        "75007300650072003000" + # FIXME: username
        "000000000000000002001c00" +
        "3100390032002e003100360038002e0031002e00320030003800" + # FIXME: ip
        #000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F
        "00003c0043003a005c00570049004e004e0054005c0053007900730074006500" +
        "6d00330032005c006d007300740073006300610078002e0064006c006c000000" +
        "a40100004700540042002c0020006e006f0072006d0061006c00740069006400" +
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000a00000005000300000000000000000000004700540042002c00" +
        "200073006f006d006d0061007200740069006400000000000000000000000000" +
        "0000000000000000000000000000000000000000000000000000030000000500" +
        "0200000000000000c4ffffff00000000270000000000")
    return unhexlify(pkt)


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4c3c2710-0bf0-4c54-8e69-aff40ffcde66
def pdu_client_confirm_active():
    pkt = (
        #000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F
        # Share Control Header
        "a401" + # totalLength
        "1300" + # pduType
        "f103" + # pduSource
        "ea030100" + # shareId
        "ea03" + # originatorId
        "0600" + # lengthSourceDescriptor
        "8e01" + # lengthCombinedCapabilities
        "4d5354534300" + # sourceDescriptor
        "0e00" + # numberCapabilities
        "0000" + # pad2Octets
        "0100" + # capabilitySetType
        "1800" + # lengthCapability
        "010003000002000000000d040000000000000000" + # capabilityData
        "0200" + # capabilitySetType
        "1c00" + # lengthCapability
        "100001000100010020035802000001000100000001000000" + #capabilityData
        "0300" + # capabilitySetType
        "5800" + # lengthCapability
        "0000000000000000000000000000000000000000010014000000010047012a00" +
        "0101010100000000010101010001010000000000010101000001010100000000" +
        "a1060000000000000084030000000000e4040000" + # capabilityData
        "1300" +
        "2800" +
        "0000000378000000780000005001000000000000000000000000000000000000" +
        "00000000" +
        "0800" +
        "0a00" +
        "010014001400" +
        "0a00" +
        "0800" +
        "06000000" +
        "0700" +
        "0c00" +
        "0000000000000000" +
        "0500" +
        "0c00" +
        "0000000002000200" +
        "0900" +
        "0800" +
        "00000000" +
        "0f00" +
        "0800" +
        "01000000" +
        "0d00" +
        "5800" +
        "010000000904000004000000000000000c000000000000000000000000000000" +
        "0000000000000000000000000000000000000000000000000000000000000000" +
        "0000000000000000000000000000000000000000" +
        "0c00" +
        "0800" +
        "01000000" +
        "0e00" +
        "0800" +
        "01000000" +
        "1000" +
        "3400" +
        "fe000400fe000400fe000800fe000800fe001000fe002000fe004000fe008000" +
        "fe000001400000080001000102000000")
    return unhexlify(pkt)


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2d122191-af10-4e36-a781-381e91c182b7


def pdu_client_persistent_key_list():
    pkt = (
        #000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F
        "49031700f103ea03010000013b031c0000000100000000000000000000000000" +
        "0000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaa")
    return unhexlify(pkt)

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/927de44c-7fe8-4206-a14f-e5517dc24b1c


def rdp_parse_serverdata(pkt, ip):
    ptr = 0
    rdp_pkt = pkt[0x49:]  # ..pkt.length]

    while ptr < len(rdp_pkt):
        header_type = rdp_pkt[ptr:ptr+1+1]
        header_length = struct.unpack("<H", rdp_pkt[ptr+2:ptr+3+1])[0]

        log.debug(f"[D] [{ip}] header: #{hexlify(header_type)} len #{header_length}")

        if header_type == b"\x02\x0c":
            log.debug(f"[D] [{ip}] security header")

            server_random = rdp_pkt[ptr+20:ptr+51+1]
            public_exponent = rdp_pkt[ptr+84:ptr+87+1]

            modulus = rdp_pkt[ptr+88:ptr+151+1]
            log.debug(f"[D] [{ip}] modulus_old #{hexlify(modulus)}")
            rsa_magic = rdp_pkt[ptr+68:ptr+71+1]
            log.debug(f"[D] [{ip}] RSA magic: #{rsa_magic}")
            if rsa_magic != b"RSA1":
                log.debug(f"[D] [{ip}] Server cert isn't RSA, this scenario isn't supported (yet).")
                raise RdpCommunicationError()
            bitlen = struct.unpack("<L", rdp_pkt[ptr+72:ptr+75+1])[0] - 8
            log.debug(f"[D] [{ip}] RSA bitlen: #{bitlen}")
            modulus = rdp_pkt[ptr+88:ptr+87+bitlen+1]
            log.debug(f"[D] [{ip}] modulus_new #{hexlify(modulus)}")

        ptr += header_length

    log.debug(f"[D] [{ip}] SERVER_MODULUS: #{hexlify(modulus)}")
    log.debug(f"[D] [{ip}] SERVER_EXPONENT: #{hexlify(public_exponent)}")
    log.debug(f"[D] [{ip}] SERVER_RANDOM: #{hexlify(server_random)}")

    rsmod = int.from_bytes(modulus, "little")
    rsexp = int.from_bytes(public_exponent, "little")
    rsran = int.from_bytes(server_random, "little")

    # log.debug(f"MODULUS  = #{hexlify(modulus)} - #{rsmod.to_s}")
    # log.debug(f"EXPONENT = #{hexlify(public_exponent)} - #{rsexp.to_s}")
    # log.debug(f"SVRANDOM = #{hexlify(server_random)} - #{rsran.to_s}")

    return rsmod, rsexp, rsran, server_random, bitlen


class RdpCommunicationError(Exception):
    pass


def rdp_send(sock, data):
    sock.send(data)
    # sock.flush
    # sleep(0.1)
    # sleep(0.5)


def rdp_recv(sock):
    res1 = sock.recv(4)
    if res1 == b'':
        raise RdpCommunicationError()  # nil due to a timeout
    version = res1[0]
    if version == 3:
        l = struct.unpack(">H", res1[2:4])[0]
    else:
        l = res1[1]
        if l & 0x80:
            l &= 0x7f
            l = l * 256 + res1[2]
    if l < 4:
        raise RdpCommunicationError()
    res2 = b''
    remaining = l - 4
    log.debug(f"Received: {hexlify(res1)} to_receive: {l:04x}")
    while remaining:
        chunk = sock.recv(remaining)
        res2 += chunk
        remaining -= len(chunk)
        # log.debug(f"Received: {(len(res2)+4):04x}")
    if res2 == b'':
        raise RdpCommunicationError()  # nil due to a timeout
    log.debug(f"Received data: {hexlify(res1+res2)}")
    return res1 + res2


def rdp_send_recv(sock, data):
    rdp_send(sock, data)
    return rdp_recv(sock)


def rdp_encrypted_pkt(data, rc4enckey, hmackey, flags=b"\x08\x00",
                      flagsHi=b"\x00\x00", channelId=b"\x03\xeb"):
    userData_len = len(data) + 12
    udl_with_flag = 0x8000 | userData_len

    pkt = b"\x02\xf0\x80"  # X.224
    pkt += b"\x64"  # sendDataRequest
    pkt += b"\x00\x08"  # intiator userId .. TODO: for a functional client this isn't static
    pkt += channelId  # channelId = 1003
    pkt += b"\x70"  # dataPriority
    # pkt += "\x80" # TODO: half of this is length field ......
    pkt += struct.pack(">H", udl_with_flag)
    pkt += flags  # {}"\x48\x00" # flags  SEC_INFO_PKT | SEC_ENCRYPT
    pkt += flagsHi  # flagsHi
    pkt += rdp_hmac(hmackey, data)[0:7+1]
    pkt += rdp_rc4_crypt(rc4enckey, data)

    tpkt = b"\x03\x00"
    tpkt += struct.pack(">H", len(pkt) + 4)
    tpkt += pkt

    return tpkt


def rdp_decrypt_pkt(data, rc4deckey, ip):
    # 000102030405060708090a0b0c0d0e0f1011121314151617
    # 0300002202f08068000103eb701480020000ff031000070000000200000004000000
    # 030001aa02f08068000103eb70819b08000000c560a0aa99ae9c07cd0e114203a53cb
    # 0300000902f0802180
    # 80b6fb733472f22b32a14d898a37aabd58913d001aa82451bd261
    # 808323c0c394f83989eec894d7493a2577048f16e23564d084cfd
    f = 0
    if data[0:2] == b'\x03\x00':
        t = data[0x07]
        log.debug(f"[D] [{ip}] Server PDU type {t:02x} {data[0:2]}")
        if t == 0x68:
            if data[0x0d] & 0x80:
                l = (data[0x0d] & 0x7f) * 256 + data[0x0e]
                s = 0x0f
            else:
                l = data[0x0d]
                s = 0x0e
            f = struct.unpack(">H", data[s:s+2])[0]
            fh = struct.unpack(">H", data[s+2:s+4])[0]
            h = data[s+4:s+4+8]
            enc_data = data[s+12:]
            log.debug(f"[D] [{ip}] Dec: len {l} flags 0x{f:04x} hash {hexlify(h)} actlen {len(enc_data)}")
    elif data[0] == 0x80:
        if data[1] & 0x80:
            s = 11
        else:
            s = 10
        enc_data = data[s:]
    else:
        return

    if data[0] == 0x80 or (f & 0x0800):
        dec_data = rdp_rc4_crypt(rc4deckey, enc_data)
        log.debug(f"[D] [{ip}] Cypher text lenght: {len(enc_data):04x}")
        log.debug(f"[D] [{ip}] Enc: {hexlify(enc_data[:40])}")
        log.debug(f"[D] [{ip}] Dec: {hexlify(dec_data[:40])}")
        # if data[0] == 0x80:
        #    sys.exit(0)


def try_check(sock, rc4enckey, hmackey, rc4deckey):
    ip, port = sock.getpeername()
    try:
        for i in range(5):
            res = rdp_recv(sock)
            rdp_decrypt_pkt(res, rc4deckey, ip)
            log.debug(f"Ignoring #{hexlify(res)[:40]}")
    except RdpCommunicationError as ex:
        # we don't care
        pass

    for j in range(6):
        log.debug(f"Sending challange x86 .. {j}")
        # x86
        pkt = rdp_encrypted_pkt(
            unhexlify("100000000300000000000000020000000000000000000000"),
            rc4enckey, hmackey, b"\x08\x00", b"\x00\x00", b"\x03\xed")
        rdp_send(sock, pkt)
        log.debug(f"Sending challange x64 .. {j}")
        # x64
        pkt = rdp_encrypted_pkt(
            unhexlify(
                "20000000030000000000000000000000020000000000000000000000000000000000000000000000"),
            rc4enckey, hmackey, b"\x08\x00", b"\x00\x00", b"\x03\xed")
        rdp_send(sock, pkt)

        try:
            for i in range(1):
                res = rdp_recv(sock)
                rdp_decrypt_pkt(res, rc4deckey, ip)
                # MCS Disconnect Provider Ultimatum PDU
                if unhexlify("0300000902f0802180") in res:
                    log.debug(f"[D] [{ip}] Received #{hexlify(res)}")
                    return STATUS_VULNERABLE
        except RdpCommunicationError as ex:
            # we don't care
            pass
    return STATUS_SAFE


def check_rdp_vuln(sock):
    ip, port = sock.getpeername()
    # check if rdp is open
    try:
        if not rdp_connect(sock):
            return STATUS_UNKNOWN
    except Exception as ex:
        log.debug(f"[D] [{ip}] Exception occured during RDP connect: {ex}")
        return STATUS_NORDP

    # send initial client data
    log.debug(f"[D] [{ip}] Sending initial client data")
    res = rdp_send_recv(sock, pdu_connect_initial())
    rsmod, rsexp, rsran, server_rand, bitlen = rdp_parse_serverdata(res, ip)

    # erect domain and attach user
    log.debug(f"[D] [{ip}] Sending erect domain request")
    rdp_send(sock, pdu_erect_domain_request())
    log.debug(f"[D] [{ip}] Sending attach user request")
    res = rdp_send_recv(sock, pdu_attach_user_request())

    user1 = struct.unpack("!H", res[9: 9+2])[0]

    # send channel requests
    log.debug(f"[D] [{ip}] Sending channel requests")
    rdp_send_recv(sock, pdu_channel_request(user1, 1009))
    rdp_send_recv(sock, pdu_channel_request(user1, 1003))
    rdp_send_recv(sock, pdu_channel_request(user1, 1004))
    rdp_send_recv(sock, pdu_channel_request(user1, 1005))
    rdp_send_recv(sock, pdu_channel_request(user1, 1006))
    rdp_send_recv(sock, pdu_channel_request(user1, 1007))
    rdp_send_recv(sock, pdu_channel_request(user1, 1008))

    #client_rand = "\xff\xee\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff"
    client_rand = b"\x41" * 32
    rcran = int.from_bytes(client_rand, "little")

    log.debug(f"[D] [{ip}] Sending security exchange PDU")
    rdp_send(sock, pdu_security_exchange(rcran, rsexp, rsmod, bitlen))

    log.debug(f"[D] [{ip}] Calculating keys")
    rc4encstart, rc4decstart, hmackey, sessblob = rdp_calculate_rc4_keys(
        client_rand, server_rand)

    log.debug(f"[D] [{ip}] RC4_ENC_KEY: #{hexlify(rc4encstart)}")
    log.debug(f"[D] [{ip}] RC4_DEC_KEY: #{hexlify(rc4decstart)}")
    log.debug(f"[D] [{ip}] HMAC_KEY: #{hexlify(hmackey)}")
    log.debug(f"[D] [{ip}] SESS_BLOB: #{hexlify(sessblob)}")

    rc4enckey = RC4(rc4encstart)
    rc4deckey = RC4(rc4decstart)

    log.debug(f"[D] [{ip}] Sending encrypted client info PDU")
    res = rdp_send_recv(sock, rdp_encrypted_pkt(
        pdu_client_info(), rc4enckey, hmackey, b"\x48\x00"))

    log.debug(f"[D] [{ip}] Received License packet: #{hexlify(res)}")
    rdp_decrypt_pkt(res, rc4deckey, ip)

    res = rdp_recv(sock)
    log.debug(f"[D] [{ip}] Received Server Demand packet: #{hexlify(res)}")
    rdp_decrypt_pkt(res, rc4deckey, ip)

    log.debug(f"[D] [{ip}] Sending client confirm active PDU")
    rdp_send(sock, rdp_encrypted_pkt(
        pdu_client_confirm_active(), rc4enckey, hmackey, b"\x38\x00"))

    log.debug(f"[D] [{ip}] Sending client synchronize PDU")
    log.debug(f"[D] [{ip}] Sending client control cooperate PDU")
    synch = rdp_encrypted_pkt(
        unhexlify("16001700f103ea030100000108001f0000000100ea03"), rc4enckey, hmackey)
    coop = rdp_encrypted_pkt(
        unhexlify("1a001700f103ea03010000010c00140000000400000000000000"), rc4enckey, hmackey)
    rdp_send(sock, synch + coop)

    log.debug(f"[D] [{ip}] Sending client control request control PDU")
    rdp_send(sock, rdp_encrypted_pkt(
        unhexlify("1a001700f103ea03010000010c00140000000100000000000000"), rc4enckey, hmackey))

    log.debug(f"[D] [{ip}] Sending client persistent key list PDU")
    rdp_send(sock, rdp_encrypted_pkt(
        pdu_client_persistent_key_list(), rc4enckey, hmackey))

    log.debug(f"[D] [{ip}] Sending client font list PDU")
    rdp_send(sock, rdp_encrypted_pkt(
        unhexlify("1a001700f103ea03010000010c00270000000000000003003200"), rc4enckey, hmackey))

    #log.debug("Sending base PDU")
    #rdp_send(sock, rdp_encrypted_pkt(unhexlify("030000001d0002000308002004051001400a000c840000000000000000590d381001cc"), rc4enckey, hmackey))

    #res = rdp_recv(sock)
    # vlog.debug_good("#{hexlify(res)}")

    result = try_check(sock, rc4enckey, hmackey, rc4deckey)

    if result == STATUS_VULNERABLE:
        # report_goods
        pass

    # Can't determine, but at least I know the service is running
    return result


def check_host(ip, port=3389):
    status = STATUS_UNKNOWN

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(5.0)
    try:
        try:
            s.connect((ip, port))
        except Exception as ex:
            log.debug(f"[D] [{ip}] Exception occured during TCP connect: {ex}")
            status = STATUS_NORDP
        else:
            try:
                status = check_rdp_vuln(s)
            except Exception as ex:
                raise ex
            finally:
                s.close()
    except Exception as ex:
        log.debug(f"[D] [{ip}] Exception: {ex}")
    return ip, status

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7c61b54e-f6cd-4819-a59a-daf200f6bf94
# mac_salt_key = "W\x13\xc58\x7f\xeb\xa9\x10*\x1e\xddV\x96\x8b[d"
# data_content = "\x12\x00\x17\x00\xef\x03\xea\x03\x02\x00\x00\x01\x04\x00$\x00\x00\x00"
# hmac = rdp_hmac(mac_salt_key, data_content) # == hexlified: "22d5aeb486994a0c785dc929a2855923"


def rdp_hmac(mac_salt_key, data_content):
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    pad1 = b"\x36" * 40
    pad2 = b"\x5c" * 48

    sha1.update(mac_salt_key)
    sha1.update(pad1)
    sha1.update(struct.pack("<L", len(data_content)))
    sha1.update(data_content)

    md5.update(mac_salt_key)
    md5.update(pad2)
    md5.update(sha1.digest())
    return md5.digest()

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/705f9542-b0e3-48be-b9a5-cf2ee582607f
#  SaltedHash(S, I) = MD5(S + SHA(I + S + ClientRandom + ServerRandom))


def rdp_salted_hash(s_bytes, i_bytes, clientRandom_bytes, serverRandom_bytes):
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    sha1.update(i_bytes)
    sha1.update(s_bytes)
    sha1.update(clientRandom_bytes)
    sha1.update(serverRandom_bytes)

    md5.update(s_bytes)
    md5.update(sha1.digest())
    return md5.digest()

#  FinalHash(K) = MD5(K + ClientRandom + ServerRandom)


def rdp_final_hash(k, clientRandom_bytes, serverRandom_bytes):
    md5 = hashlib.md5()

    md5.update(k)
    md5.update(clientRandom_bytes)
    md5.update(serverRandom_bytes)
    return md5.digest()


def rdp_calculate_rc4_keys(client_random, server_random):
    # preMasterSecret = First192Bits(ClientRandom) + First192Bits(ServerRandom)
    preMasterSecret = client_random[0:23+1] + server_random[0:23+1]

    #  PreMasterHash(I) = SaltedHash(preMasterSecret, I)
    #  MasterSecret = PreMasterHash(0x41) + PreMasterHash(0x4242) + PreMasterHash(0x434343)
    masterSecret = rdp_salted_hash(preMasterSecret, b"A", client_random, server_random) + rdp_salted_hash(
        preMasterSecret, b"BB", client_random, server_random) + rdp_salted_hash(preMasterSecret, b"CCC", client_random, server_random)

    # MasterHash(I) = SaltedHash(MasterSecret, I)
    # SessionKeyBlob = MasterHash(0x58) + MasterHash(0x5959) + MasterHash(0x5A5A5A)
    sessionKeyBlob = rdp_salted_hash(masterSecret, b"X", client_random, server_random) + rdp_salted_hash(
        masterSecret, b"YY", client_random, server_random) + rdp_salted_hash(masterSecret, b"ZZZ", client_random, server_random)

    # InitialClientDecryptKey128 = FinalHash(Second128Bits(SessionKeyBlob))
    initialClientDecryptKey128 = rdp_final_hash(
        sessionKeyBlob[16:31+1], client_random, server_random)

    # InitialClientEncryptKey128 = FinalHash(Third128Bits(SessionKeyBlob))
    initialClientEncryptKey128 = rdp_final_hash(
        sessionKeyBlob[32:47+1], client_random, server_random)

    macKey = sessionKeyBlob[0:15+1]

    log.debug(f"PreMasterSecret = #{hexlify(preMasterSecret)}")
    log.debug(f"MasterSecret = #{hexlify(masterSecret)}")
    log.debug(f"sessionKeyBlob = #{hexlify(sessionKeyBlob)}")
    log.debug(f"macKey = #{hexlify(macKey)}")
    log.debug(f"initialClientDecryptKey128 = #{hexlify(initialClientDecryptKey128)}")
    log.debug(f"initialClientEncryptKey128 = #{hexlify(initialClientEncryptKey128)}")

    return initialClientEncryptKey128, initialClientDecryptKey128, macKey, sessionKeyBlob


def rsa_encrypt(bignum, rsexp, rsmod):
    return pow(bignum, rsexp, rsmod)


def rdp_rc4_crypt(rc4obj, data):
    return rc4obj.crypt(data)


def int_to_bytestring(daInt):
    return daInt.to_bytes((daInt.bit_length() + 7) // 8, byteorder='little')


def configure_logging(enable_debug, logfile):
    if enable_debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
    if logfile:
        # create file handler
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)
        # create formatter and add it to the handlers
        formatter = logging.Formatter(
            "%(asctime)s - %(process)d - %(name)s - %(levelname)s - %(message)r"
        )
        fh.setFormatter(formatter)
        log.addHandler(fh)
    # create console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s %(message)r"
    )
    ch.setFormatter(formatter)
    log.addHandler(ch)

    log.info("Starting %s" % __file__)
    log.info(" ".join(sys.argv))
    #abspath = os.path.abspath(__file__)
    #dname = os.path.dirname(abspath)
    #os.chdir(dname)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version=f'{os.path.basename(__file__)} 0.1')
    parser.add_argument('-d', '--debug', action='store_true', help='verbose output')
    parser.add_argument('-l', '--logfile', nargs="?", help='log to file')
    parser.add_argument('-w', '--workers', type=int, default=300, help='number of parallel worker tasks')
    parser.add_argument('host', nargs="*", help='List of targets (addresses or subnets)')
    args = parser.parse_args()

    if not args.host:
        parser.print_help()
        return

    configure_logging(args.debug, args.logfile)

    ips = []
    for ip in args.host:
        cmd = True
        ips += [addr.exploded for addr in IPv4Network(ip, strict=False)]
    th = []
    ips = set(ips)
    log.info(f"Going to scan {len(ips)} hosts, in {args.workers} parallel tasks")
    # with progressbar.ProgressBar(max_value=len(ips)) as bar:
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        for ip in ips:
            ft_dp = executor.submit(check_host, ip)
            th.append(ft_dp)
        for r in concurrent.futures.as_completed(th):
            ip, status = r.result()
            # if STATUS_NORDP in status:
            #    continue
            mark = '+' if status == STATUS_VULNERABLE else '-'
            log.info(f"[{mark}] [{ip}] Status: {status}")


if __name__ == "__main__":
    main()
