# -*- coding: utf-8 -*-
"""
"""

import hmac
import hashlib
import random
import struct
import math
import base64


class Salt(object):
  generator = random.SystemRandom()

  @classmethod
  def gen(cls, k):
    res = ""
    for _ in xrange(0, k / 4):
      res += struct.pack(">L", cls.randint())
    return res[:k]
  
  @classmethod
  def randint(cls):
    try:
      return cls.generator.randint(0, 0xFFFFFFFF)
    except NotImplementedError:
      cls.generator = random.Random()
      return cls.generator.randint(0, 0xFFFFFFFF)


class Hash(object):
  def __init__(self, name, salt_length, stretch):
    self.name = name
    self.salt_length = salt_length
    self.stretch = stretch

  def key(self, password):
    salt = Salt.gen(self.salt_length)
    hash_func = getattr(hashlib, self.name)
    hash_length = hash_func().digest_size
    key = pbkdf2(password, salt, self.stretch, hash_length, hash_func)
    encoded_salt = _b64encode(salt)
    encoded_key = _b64encode(key)
    return "%s$%d$%s$%s" % (self.name, self.stretch, encoded_salt, encoded_key)


DefaultHash = Hash(name="sha256", salt_length=16, stretch=10000)


def key(password):
  return DefaultHash.key(password)


def check(password, target):
  params = target.split("$")
  assert len(params) == 4, target
  stretch = int(params[1])
  salt = _b64decode(params[2])
  key_str = params[3]
  hash_name = params[0]
  hash_func = getattr(hashlib, hash_name)
  hash_length = hash_func().digest_size
  val = pbkdf2(password, salt, stretch, hash_length, hash_func)
  val_str = _b64encode(val)
  return val_str == key_str


def _b64decode(s):
  pad = len(s) % 4
  if pad > 0:
    s += ("=" * pad)
  return base64.standard_b64decode(s)


def _b64encode(s):
  return base64.standard_b64encode(s).rstrip('=')


def _strxor(a, b): 
  return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])


def pbkdf2(password, salt, stretch, key_len, hash_func):
  hash_len = hash_func().digest_size
  num_blocks = (key_len + hash_len - 1) / hash_len
  blocks = []
  for block in xrange(1, num_blocks + 1):
    blk = struct.pack(">L", block)
    dk = hmac.new(password, salt + blk, hash_func).digest()
    tmp = dk
    for _ in xrange(stretch - 1):
      dk = hmac.new(password, dk, hash_func).digest()
      tmp = _strxor(tmp, dk)
    blocks.append(tmp)
  buf = "".join(blocks)
  return buf[:key_len]


def _test():
  pairs = [
    ("hoge", "sha256$10000$p0nHKolS3wrd2N/xHADDFg$YuM6M/WzwJjGZXxE8S6XLkbXWI4q3cTTUGGgnyixTQA"),
    ("test", "sha256$10000$Rc0tB8YsFnplpES06sOs+g$92urj/669QF2qZ/Y1QRgPIjTa1hulKdcA29sFPBRHo8"),
    ("hello world", "sha256$10000$NBGNBelcvz6W+P9IO8W6SQ$rcqRewl8U2PBZUDlQPKM0OVv1sLHvgUSu8VDZ3z1BEw"),
  ]
  for raw, key in pairs:
    if check(raw, key):
      print("%s ok" % raw)
    else:
      print("%s failed" % raw)


def _main():
  import sys
  mode = sys.argv[1]
  if mode == "-c":
    print check(sys.argv[2], sys.argv[3])
  elif mode == "-k":
    print key(sys.argv[2])
  elif mode == "-t":
    _test()

if __name__ == '__main__':
  _main()
