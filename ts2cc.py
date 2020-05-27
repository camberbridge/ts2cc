import sys
from optparse import OptionParser
import argparse
import hashlib
from collections import defaultdict
from io import BufferedReader, FileIO
from aribgaiji import GAIJI_MAP
import struct
from data_group import DataGroup
from closed_caption import next_data_unit
from closed_caption import StatementBody
from ass import ASSFormatter
import traceback

class FileOpenError(Exception):
  def __init__(self, msg='No further info'):
    self._msg = msg

class DRCSString(object):
  """DRCS文字列"""
  images = {
    '8473bbfc8870eb44e2124f36ded70f34': '凜',
    '20c5bf5ad460814c4627fa9abe1b5389': '蜻',
    'f47249bc346fe4194b933b09571cab7d': '((',
    '618a99e2a0640543bb18ea8269f78f4b': '((',
    'c6ebb54b066867774f42a247df7a6c1b': '))',
    '094fd4e8b58d5c1f016f6cc695c9c8dd': '))',
    '7bb547a3336fb28775ed4b31ccea2c61': '「',
    '78bea8412561249617d2cf8c624a00a6': '」',
    '60bd03df9faa250e0f797d719df1320c': '⁈',
    '9c0ac7f2b2f81acb81b9000e7d8ff56a': '📱',
    'd27350b838145fe4433102121e2ba56b': '📱',
    '881edb7f0adc96d25b056f016d2ddd86': '📱',
    'b0f1dabe3e27571f654b4196aa7f27e7': '📢',
    '24c1bf547f713a666ed983852a8f2fbb': '📢',
    '19ec594cff4ebf2f56e5fd1799f89142': '💻',
  }

  def __init__(self, bitmap, depth, width, height):
    self.bitmap = bitmap
    self.md5hash = hashlib.md5(str(bitmap).encode('UTF-8')).hexdigest()
    self.depth = depth
    self.width = width
    self.height = height

  def image(self):
    result = []
    for i in range(0, self.height * 2, 2):
      char = (self.bitmap[i] << 8) | self.bitmap[i+1]
      result.append(format(char, ' 16b').replace('0', ' ').replace('1', '■'))
    return '\n'.join(result)

  def detail(self):
    image = self.image()
    return "{}\n{}".format(image, self.md5hash)

  def __str__(self):
    return self.images.get(self.md5hash, self.detail())

class CProfileString(object):
  """CProfile文字列"""
  mapping = {
    0: ' ',
    7: '\a',
    12: '\n',
    13: '\n',
    32: ' ',
  }

  drcs = {}

  def __new__(cls, data, options):
    if options.color:
      cls.mapping.update({
        0x80: '\033[30m',
        0x81: '\033[31m',
        0x82: '\033[32m',
        0x83: '\033[33m',
        0x84: '\033[34m',
        0x85: '\033[35m',
        0x86: '\033[36m',
        0x87: '\033[37m',
      })
    return object.__new__(cls)

  def __init__(self, data, options):
    self.data = data

  def __iter__(self):
    return self

  def __next__(self):
    return next(self.character())

  def character(self):
    """Genarator returns each charcter as an Unicode type.
    """
    while self.data:
      char1 = self.data.pop(0)
      if 0xa0 < char1 < 0xff:
        char2 = self.data.pop(0)
        try:
          yield bytes((char1, char2)).decode('euc-jp')
        except UnicodeDecodeError:
          gaiji = ((char1 & 0x7f) << 8) | (char2 & 0x7f)
          if gaiji == 0x7c21:
            # An arrow indicating that subtitles continues to the next packet.
            continue
          try:
            yield GAIJI_MAP[gaiji]
          except KeyError:
            yield '(0x{:x}{:x})'.format(char1, char2)
      elif options.drcs and 0x20 < char1 < 0x2f:
        yield str(self.drcs.get(char1, '(0x{:x})'.format(char1)))
      elif char1 in self.mapping:
        yield self.mapping[char1]

  def __str__(self):
    return ''.join(self)

def get_packet(ts, target_pids):
  """Generator returns a TS dict for the targeted PID.
  ts: TS file to get(target).
  target_pids: PID list to get(target).
  """
  buf = defaultdict(bytearray)
  for packet in ts:
    payload_unit_start_indicator = (packet[1] & 0x40) >> 6
    pid = ((packet[1] & 0x1F) << 8) | packet[2]
    has_adaptation = (packet[3] & 0x20) >> 5
    has_payload = (packet[3] & 0x10) >> 4
    if pid in target_pids:
      payload_index = 4
      if has_adaptation:
        adaptation_field_length = packet[payload_index]
        payload_index += adaptation_field_length + 1
      if has_payload:
        if payload_unit_start_indicator:
          if buf[pid]:
            yield buf[pid]
            del buf[pid]
          if packet[payload_index:payload_index+3] != b'\x00\x00\x01':
            pointer_field = packet[payload_index]
            payload_index += pointer_field + 1
        buf[pid].extend(packet[payload_index:])

def get_program_map_PIDs(ts):
  """Generator returns PMT ID from the PAT.
  """
  packet = next(get_packet(ts, [0x00]))
  table_id = packet[0]
  section_length = ((packet[1] & 0x0F) << 8) | packet[2]
  map_index = 8
  crc_index = section_length - 4
  while map_index < crc_index:
    program_number = (packet[map_index] << 8) | packet[map_index+1]
    program_map_PID = ((packet[map_index+2] & 0x1F) << 8) | packet[map_index+3]
    map_index += 4
    if program_number != 0:
      yield program_map_PID

def get_caption_pid(packets, full_ts_flag):
  """Return a caption packet PID from the PMT.
  """
  for packet in packets:
    table_id = packet[0]
    section_length = ((packet[1] & 0x0F) << 8) | packet[2]
    program_number = (packet[3] << 8) | packet[4]
    program_info_length = ((packet[10] & 0x0F) << 8) | packet[11]
    map_index = 12 + program_info_length
    crc_index = section_length - 4

    if full_ts_flag:
      while map_index < crc_index:
        stream_type = packet[map_index]
        elementary_PID = ((packet[map_index+1] & 0x1F) << 8) | packet[map_index+2]
        ES_info_length = ((packet[map_index+3] & 0x0F) << 8) | packet[map_index+4]
        last = map_index + 5 + ES_info_length
        descriptors = parse_descriptor(packet[map_index+5:last])
        map_index = last
        if (stream_type == 0x06 and 0x52 in descriptors and descriptors[0x52][0][2] == 0x87):
          print("Caption pid = ", elementary_PID)
          return elementary_PID

def parse_caption(packet, options):
  """Generator returns caption texts from the caption packt.
  """
  PES_header_data_length = packet[8]
  PTS = (((packet[9] & 0x0E) << 29) |
         (packet[10] << 22) | ((packet[11] & 0xFE) << 14) |
         (packet[12] << 7) | ((packet[13] & 0xFE) >> 1))
  PES_data_packet_header_length = packet[11 + PES_header_data_length] & 0x0F
  index = 12 + PES_header_data_length + PES_data_packet_header_length
  data_group_id = (packet[index] & 0xFC) >> 2
  data_group_size = (packet[index+3] << 8) | packet[index+4]
  if data_group_id in (0x00, 0x20):
    num_languages = packet[index+6]
    index += 7 + num_languages * 5
  else:
    index += 6
  data_unit_loop_length = ((packet[index] << 16) | packet[index+1] << 8) | packet[index+2]
  loop_index = 0
  while loop_index < data_unit_loop_length:
    data_unit_parameter = packet[index+4+loop_index]
    data_unit_size = ((packet[index+5+loop_index] << 16) | packet[index+6+loop_index] << 8) | packet[index+7+loop_index]
    last = index + 8 + loop_index + data_unit_size
    if data_unit_parameter == 0x20:
      data_unit_data = packet[index+8+loop_index:last]
      a(data_unit_data)
      yield data_unit_data
    elif options.drcs and data_unit_parameter == 0x30:
      data_unit_data = packet[index+8+loop_index:last]
      i = 0
      for _ in range(data_unit_data[0]):
        character_code_1 = data_unit_data[i+1]
        character_code_2 = data_unit_data[i+2]
        num_font = data_unit_data[i+3]
        font_id = (data_unit_data[i+4] & 0xF0) >> 4
        mode = data_unit_data[i+4] & 0x0F
        if mode == 0 or mode == 1:
          depth = data_unit_data[i+5]
          width = data_unit_data[i+6]
          height = data_unit_data[i+7]
          bitmap = data_unit_data[i+8:i + 8 + height * 2]
          CProfileString.drcs[character_code_2] = DRCSString(bitmap, depth, width, height)
          i += 7 + height * 2

    loop_index += data_unit_size + 5

def a(packet):
  """
  for p in packet:
    print(format(p, '02X'), end=' ')
  print()
  """

def parse_descriptor(packet):
  total_length = len(packet)
  index = 0
  result = defaultdict(list)
  while index < total_length:
    tag = packet[index]
    length = packet[index+1]
    last = index + length + 2
    result[tag].append(packet[index:last])
    index = last
  return result

class TS(object):
  PACKET_SIZE = 188
  
  # Sync byte
  SYNC_BYTE_INDEX = 0
  SYNC_BYTE = 0x47
  
  # Transport Error Indicator (TEI)
  TEI_INDEX = 1
  TEI_MASK = 0x80

  # Payload Unit Start Indicator (PUSI)
  PUSI_INDEX = 1
  PUSI_MASK = 0x40

  #Packt ID (PID)
  PID_START_INDEX = 1
  PID_LENGTH_BYTES = 2
  PID_MASK = 0x1fff

  # Transport Scrambling Control (TSC)
  TSC_INDEX = 3
  TSC_MASK = 0xc0

  # Adaptation field control
  ADAPTATION_FIELD_CONTROL_INDEX = 3
  ADAPTATION_FIELD_CONTROL_MASK = 0x30
  NO_ADAPTATION_FIELD = 0b01
  ADAPTATION_FIELD_ONLY = 0b10
  ADAPTATION_FIELD_AND_PAYLOAD = 0b11
  ADAPTATION_FIELD_RESERVED = 0b00

  # Continuity counter
  CONTINUITY_COUNTER_INDEX = 3
  CONTINUITY_COUNTER_MASK = 0x0f

  # Adaptation field data (if present)
  ADAPTATION_FIELD_LENGTH_INDEX = 4
  ADAPTATION_FIELD_DATA_INDEX = 5

  # Program Clock Reference (PCR)
  # Present flag tagged in ADAPTATION_FIELD_DATA_INDEX byte
  PCR_FLAG_MASK = 0x10
  PCR_START_INDEX = 6 
  PCR_SIZE_BYTES = 6

class ES:
  """ very minimalistic Elementary Stream handling
  """
  STREAM_ID_INDEX = 3

class TransportStreamFile(BufferedReader):
  def __init__(self, path):
    BufferedReader.__init__(self, FileIO(path))
    self._elementary_streams = {}

  def __next__(self):
    packet = bytearray(self.read(188))

    if len(packet) != TS.PACKET_SIZE:
      raise StopIteration

    if packet[0] != TS.SYNC_BYTE:
      start_byte = 0
      for i in range(start_byte, TS.PACKET_SIZE):
        if packet[i] == TS.SYNC_BYTE:
          start_byte = i
          break
      if start_byte == 0:
        raise Exception("failure to find sync byte in ts packet size.")
        next(self)
      remainder = bytearray(self.read(TS.PACKET_SIZE - start_byte))
      packet = packet[start_byte:] + remainder

    pusi = get_payload_start(packet)
    pid = get_pid(packet)
    adaptation_field_control = get_adaptation_field_control(packet)
    continuity_counter = get_continuity_counter(packet)
    payload = get_payload(packet)

    if pusi == True:
      if not pes_packet_check_formedness(payload):
        if pid in self._elementary_streams:
          self._elementary_streams[pid] = None
        return packet # TODO: modify
      pes_id = get_pes_stream_id(payload)
      self._elementary_streams[pid] = payload
    else:
      if pid in self._elementary_streams:
        if not self._elementary_streams[pid]:
          self._elementary_streams[pid] = ""
        self._elementary_streams[pid] += payload
      else:
        pass
    if pid in self._elementary_streams and pes_packet_complete(self._elementary_streams[pid]):
      es = self._elementary_streams[pid]
      header_size = get_pes_header_length(es)
      #self.OnESPacket(pid, es, header_size) # TODO
      OnESPacket(pid, es, header_size)

    return packet

##### TS #####
def get_payload_start(packet):
  return (packet[TS.PUSI_INDEX] & TS.PUSI_MASK) != 0
def get_pid(packet):
  return ((packet[TS.PID_START_INDEX] & 0x1f)<<8) | packet[TS.PID_START_INDEX+1]
def get_adaptation_field_control(packet):
  return (packet[TS.ADAPTATION_FIELD_CONTROL_INDEX] & TS.ADAPTATION_FIELD_CONTROL_MASK) >> 4
def get_continuity_counter(packet):
  return packet[TS.CONTINUITY_COUNTER_INDEX] & TS.CONTINUITY_COUNTER_MASK
def get_adaptation_field_control(packet):
  return (packet[TS.ADAPTATION_FIELD_CONTROL_INDEX] & TS.ADAPTATION_FIELD_CONTROL_MASK) >> 4
def get_adaptation_field_length(packet):
  if get_adaptation_field_control(packet) == TS.NO_ADAPTATION_FIELD:
    return 0
  return packet[TS.ADAPTATION_FIELD_LENGTH_INDEX] + 1
def get_payload(packet):
  adaptation_field_len = get_adaptation_field_length(packet)
  header_size = 4 + adaptation_field_len
  return packet[header_size:]
##### ES #####
def pes_packet_check_formedness(payload):
  b1 = payload[0]
  b2 = payload[1]
  b3 = payload[2]
  b4 = payload[3]
  if b1 != 0 or b2 != 0 or b3 != 1:
    return False
  return True
def get_pes_stream_id(payload):
  return payload[ES.STREAM_ID_INDEX]
def get_pes_packet_length(payload):
  if len(payload)<6:
    return 0
  return struct.unpack('>H', payload[4:6])[0] + 6
def pes_packet_complete(payload):
  pes_packet_len = get_pes_packet_length(payload)
  payload_len = len(payload)
  return pes_packet_len == payload_len
def get_pes_header_length(payload):
  if len(payload) < 9:
    return 0
  return 6 + 3 + payload[8]
def get_pes_payload(payload):
  payload_start = get_pes_header_length(payload)
  return payload[payload_start:]

##### ES Parser #####
# GLOBALS TO KEEP TRACK OF STATE
initial_timestamp = None
elapsed_time_s = 0
pid = -1
VERBOSE = False
SILENT = False
DEBUG = False
ass = None
infilename = ""
outfilename = ""
tmax = 0
parser = argparse.ArgumentParser(description='Remove ARIB formatted Closed Caption information from an MPEG TS file and format the results as a standard .ass subtitle file.')
parser.add_argument('infile', help='Input filename (MPEG2 Transport Stream File)', type=str)
parser.add_argument('-o', '--outfile', help='Output filename (.ass subtitle file)', type=str, default=None)
args = parser.parse_args()
infilename = args.infile
outfilename = infilename + ".ass"
if args.outfile is not None:
  outfilename = args.outfile
def OnESPacket(current_pid, packet, header_size):
  global pid
  global VERBOSE
  global SILENT
  global elapsed_time_s
  global ass
  global infilename
  global outfilename
  global tmax
  global time_offset

  if pid >= 0 and current_pid != pid:
    return

  try:
    payload = get_pes_payload(packet)
    f = list(payload)
    data_group = DataGroup(f)
    if not data_group.is_management_data():
      caption = data_group.payload()
      for data_unit in next_data_unit(caption):
        if not isinstance(data_unit.payload(), StatementBody):
          continue

        if not ass:
          v = not SILENT
          ass = ASSFormatter(tmax=tmax, video_filename=outfilename, verbose=v)

        #ass.format(data_unit.payload().payload(), elapsed_time_s)

    else:
      management_data = data_group.payload()
      numlang = management_data.num_languages()
      if pid < 0 and numlang > 0:
        print("++++++++++++++++++++++")
        pid = current_pid

  except EOFError:
    pass
  except FileOpenError as ex:
    raise ex
  except Exception:
    if not SILENT and pid >= 0:
      print("Exception thrown while handling DataGroup in ES. This may be due to many factors"
        + "such as file corruption or the .ts file using as yet unsupported features.")
      traceback.print_exc(file=sys.stdout)


if __name__ == '__main__':
  parser = OptionParser('usage: %prog [option] [in] [out]')
  parser.add_option('-c', '--color', action='store_true',dest='color', default=False,help='color mode')
  parser.add_option('-d', '--drcs', action='store_true',dest='drcs', default=False,
                    help='display DRCS image to stdout')
  options, args = parser.parse_args()

  try:
    inpath = args[0]
    outpath = args[1] if len(args) > 2 else '-'
  except IndexError:
    sys.exit(parser.print_help())

  path = sys.stdin.fileno() if inpath == '-' else inpath
  out = sys.stdout if outpath == '-' else open(outpath, 'w')

  with TransportStreamFile(path) as ts:
    pmt_pids = list(get_program_map_PIDs(ts))
    print("PMT_PIDs: ", pmt_pids)

    # Parse packets regardless of Full TS or limited TS.
    if len(pmt_pids) > 2:
      caption_pid = [get_caption_pid(get_packet(ts, pmt_pids), True)]
    else:
      caption_pid = [get_caption_pid(get_packet(ts, pmt_pids), False)]
    print("Caption_PID: ", caption_pid)

    if caption_pid[0] is not None:
      for pes in get_packet(ts, caption_pid):
        for caption in parse_caption(pes, options):
          out.write(str(CProfileString(caption, options)))
          out.flush()
    print("\nFiniesh!!!")
