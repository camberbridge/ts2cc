import sys
import traceback
from closed_caption import CaptionStatementData
from closed_caption import CaptionManagementData
from struct import error as struct_error
from copy import copy
import struct

DEBUG = False


class EOFError(Exception):
  """ Custom exception raised when we read to EOF
  """
  pass

class DataGroupParseError(Exception):
  """ Custom Exception generated when parsing a DataGroup from a binary stream
  """
  pass

def split_buffer(length, buf):
  '''split provided array at index x
  '''
  a = []
  if len(buf)<length:
    return (a, buf)

  for i in range(length):
    a.append(buf.pop(0))
  return (a,buf)

def ucb(f):
  '''Read unsigned char byte from binary file
  '''
  if isinstance(f, list):
    if len(f) < 1:
      raise EOFError()
    b, f = split_buffer(1, f)

    return b[0]
  else:
    _f = f.read(1)
    if len(_f) < 1:
      raise EOFError()

    return _f[0]

def usb(f):
  '''Read unsigned short from binary file
  '''
  if isinstance(f, list):
    n, f = split_buffer(2, f)

    return n[0]
  else:
    _f = f.read(2)
    if DEBUG:
      print("usb: " + hex(_f[0]) + ":" + hex(_f[1]))
    if len(_f) < 2:
      raise EOFError()

    return _f[0]

class DataGroup(object):
  '''Represents an arib Data Group packet structure as
  described in ARIB b-24 Table 9-1 on pg 172
  '''
  GroupA_Caption_Management = 0x0
  GroupB_Caption_Management = 0x20
  GroupA_Caption_Statement_lang1 = 0x1
  GroupA_Caption_Statement_lang2 = 0x2
  GroupA_Caption_Statement_lang3 = 0x3
  GroupA_Caption_Statement_lang4 = 0x4
  GroupA_Caption_Statement_lang5 = 0x5
  GroupA_Caption_Statement_lang6 = 0x6
  GroupA_Caption_Statement_lang7 = 0x7
  GroupA_Caption_Statement_lang8 = 0x8

  def __init__(self, f):
    if DEBUG:
      print("__DATA_GROUP_START__")

    self._stuffing_byte = ucb(f)
    if DEBUG:
      print(hex(self._stuffing_byte))
    if(self._stuffing_byte is not 0x80):
      raise DataGroupParseError("Initial stuffing byte not equal to 0x80: " + hex(self._stuffing_byte))

    self._data_identifier = ucb(f)
    if DEBUG:
      print(hex(self._data_identifier))
    if self._data_identifier is not 0xff:
      raise DataGroupParseError("Initial data identifier is not equal to 0xff" + hex(self._data_identifier))

    self._private_stream_id = ucb(f)
    if DEBUG:
     print(hex(self._private_stream_id))
    if self._private_stream_id is not 0xf0:
      raise DataGroupParseError("Private stream id not equal to 0xf0: " + hex(self._private_stream_id))

    self._group_id = ucb(f)
    if DEBUG:
        print('group id ' + str((self._group_id >> 2)&(~0x20)))
    self._group_link_number = ucb(f)
    if DEBUG:
        print(str(self._group_link_number))
    self._last_group_link_number = ucb(f)
    if DEBUG:
      print(str(self._last_group_link_number))
    if self._group_link_number != self._last_group_link_number:
      print("This is data group packet " + str(self._group_link_number) + " of " + str(self._last_group_link_number))
    self._data_group_size = usb(f)
    if DEBUG:
      print('data group size found is ' + str(self._data_group_size))

    if not self.is_management_data():
      self._payload = CaptionStatementData(f)
    else:
      self._payload = CaptionManagementData(f)
    
    self._crc = usb(f)
    if DEBUG:
      print('crc value is ' + str(self._crc))

    # TODO: check CRC value

  def payload(self):
    return self._payload

  def is_management_data(self):
    '''Estimate whether the payload of this packet is 
    caption management data (as opposed to caption data itself.
    There appears to be some deviation from the standard, which
    states that the top 6 bits of _group_id should be zero or 0x20
    to qualify as management data.
    '''
    return ((self._group_id >> 2)&(~0x20))==0
