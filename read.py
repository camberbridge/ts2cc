import struct

DEBUG = False

class EOFError(Exception):
  """ Custom exception raised when we read to EOF
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

def dump_list(list):
  print(' '.join('{:#x}'.format(x) for x in list))

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
    return struct.unpack('>H', ''.join(n))[0]
  else:
    _f = f.read(2)
    if DEBUG:
      print("usb: " + hex(ord(_f[0])) + ":" + hex(ord(_f[1])))
    if len(_f) < 2:
      raise EOFError()
    return struct.unpack('>H', _f)[0]

def ui3b(f):
  '''Read 3 byte unsigned short from binary file
  '''
  if isinstance(f, list):
    n, f = split_buffer(3, f)

    return n[-1:]
  else:
    _f = f.read(3)
    if len(_f) < 3:
      raise EOFError()

    return _f[-1:]

def uib(f):
  if isinstance(f, list):
    n, f = split_buffer(4, f)
    return struct.unpack('>L', ''.join(n))[0]
  else:
    _f = f.read(4)
    if len(_f) < 4:
      raise EOFError()
 
    return struct.unpack('>L', _f)[0]

def ulb(f):
  '''Read unsigned long long (64bit integer) from binary file
  '''
  if isinstance(f, list):
    n, f = split_buffer(8, f)
    return struct.unpack('>Q', ''.join(n))[0]
  else:
    _f = f.read(8)
    if len(_f) < 8:
      raise EOFError()
    return struct.unpack('>Q', _f)[0]


def buffer(f, size):
  '''Read N bytes from either a file or list
  '''
  if isinstance(f, list):
    n, f = split_buffer(size, f)
    return ''.join(n)
  else:
    _f = f.read(size)
    if len(_f) < size:
      raise EOFError()
 
    return _f

