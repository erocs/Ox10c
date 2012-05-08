import itertools
import random
import struct

next_word_values = [i for i in itertools.chain(
  xrange(0x10, 0x17+1),
  (0x1A,),
  xrange(0x1E, 0x1F+1))]
all_a_values = (xrange(0x00, 0x3F+1))
all_b_values = (xrange(0x00, 0x1F+1))

normal_ops = [i for i in xrange(0x01, 0x1f+1)
              if i not in (0x18, 0x19, 0x1C, 0x1D)]
extended_ops = [
    0x20, 0x100, 0x120, 0x140, 0x160, 0x180,
    0x200, 0x220, 0x240]

with open('dcpu16.test', 'wb') as fo:
  for i in xrange(2048):
    extra_words = 0
    val_a = random.choice(all_a_values)
    if val_a in next_word_values:
      extra_words += 1
    val_a <<= 10
    if random.randint(0, 1) == 0:
      op = random.choice(normal_ops)
      val_b = random.choice(all_b_values)
      if val_b in next_word_values:
        extra_words += 1
      val_b <<= 5
      word = val_a | val_b | op
      print '%04x %04x %04x %04x' % (word, val_a, val_b, op)
    else:
      op = random.choice(extended_ops)
      word = val_a | op
      print '%04x %04x %04x' % (word, val_a, op)
    words = [struct.pack('>H', word)]
    for i in xrange(extra_words):
      rand_word = random.randint(0, 0xFFFF)
      words.append(struct.pack('>H', rand_word))
      print '%04x' % (rand_word,)
    fo.write(''.join(words))
