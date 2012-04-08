# ----------------------------------------------------------------------
# DCPU-16 bytecode processor module
# Based on IDA's EFI Byte code processor
# (c) 2012

import sys
import idaapi
from idaapi import *

PLFM_DCPU16 = 0x8442


class Error(Exception):
  def __init__(self, msg):
    super(Error, self).__init__()
    self.msg = msg


class InvalidOperand(Error):
  pass


def dbgprint(msg, *args):
  pass
  #if len(args) > 0:
  #  print msg % args
  #else:
  #  print msg


class dcpu16_processor_t(idaapi.processor_t):
    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = PLFM_DCPU16

    # Processor features
    flag = PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE | PR_CNDINSNS

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['dcpu16']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['0x10c DCPU-16']

    # size of a segment register in bytes
    segreg_size = 0

    # Array of typical code start sequences (optional)
    #codestart = ['\x60\x00']  # 60 00 xx xx: MOVqw         SP, SP-delta

    # Array of 'return' instruction opcodes (optional)
    retcodes = ['\x61\xC1']

    # You should define 2 virtual segment registers for CS and DS.
    # Let's call them rVcs and rVds.

    # icode of the first instruction
    instruc_start = 0

    # Size of long double (tbyte) for this processor
    # (meaningful only if ash.a_tbyte != NULL)
    tbyte_size = 0

    # only one assembler is supported
    # most of this stuff is bogus and needs to be tuned for a real assembler
    assembler = {
        # flag
        'flag' : ASH_HEXF3 | ASD_DECF0 | ASO_OCTF1 | ASB_BINF0,

        # user defined flags (local only for IDP)
        # you may define and use your own bits
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "0x10c DCPU-16 bytecode assembler",

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "",

        # remove if not allowed
        'a_qword': "",

        # remove if not allowed
        'a_oword': "",

        # float;  4bytes; remove if not allowed
        'a_float': "",

        # double; 8bytes; NULL if not allowed
        'a_double': "",

        # long double;    NULL if not allowed
        'a_tbyte': "",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string)
        'a_sizeof_fmt': "size %s",
    } # Assembler


    # ======================================================================
    # Operand decoding
    # ======================================================================

    VAL_REGISTER = range(0x00, 0x07)
    VAL_REGISTER_PTR = range(0x08, 0x0F)
    VAL_REGISTER_PTR_PLUS_WORD = range(0x10, 0x17)
    VAL_POP_STACK = (0x18,)
    VAL_PEEK_STACK = (0x19,)
    VAL_PUSH_STACK = (0x1A,)
    VAL_REGISTER_SP = (0x1B,)
    VAL_REGISTER_PC = (0x1C,)
    VAL_REGISTER_O = (0x1D,)
    VAL_NEXT_WORD_PTR = (0x1E,)
    VAL_NEXT_WORD = (0x1F,)
    VAL_LITERAL = range(0x20, 0x3F)
    REGISTER_FAKE_INDEX = 8
    REGISTER_PC = 9
    REGISTER_SP = 10
    REGISTER_O = 11

    def get_op_by_num(self, operand_num):
      if operand_num == 1:
        return self.cmd.Op1
      if operand_num == 2:
        return self.cmd.Op2
      if operand_num == 3:
        return self.cmd.Op3
      if operand_num == 4:
        return self.cmd.Op4
      if operand_num == 5:
        return self.cmd.Op5
      if operand_num == 6:
        return self.cmd.Op6
      return None

    def register_operand(self, operand_num, op_value):
      value = op_value
      operand = self.get_op_by_num(operand_num)
      operand.dtyp = dt_word
      operand.flags = 0x08

      # Retrieve extra data if operand specifies
      extra_op_len = 0
      extra = None
      if (value in self.VAL_REGISTER_PTR_PLUS_WORD or
          value in self.VAL_NEXT_WORD_PTR or
          value in self.VAL_NEXT_WORD):
        extra = (ua_next_byte() << 8) + ua_next_byte()
        extra_op_len = 2
        dbgprint('register_operand extra 0x%04x', extra)

      # Parse operand
      if value in self.VAL_REGISTER:
        operand.type = o_reg
        operand.reg = value
        dbgprint('register_operand VAL_REGISTER 0x%04x', operand.reg)

      elif value in self.VAL_REGISTER_PTR:
        operand.type = o_phrase
        operand.reg = value - 0x08
        #operand.phrase = self.REGISTER_FAKE_INDEX
        dbgprint('register_operand VAL_REGISTER_PTR 0x%04x', operand.reg)

      elif value in self.VAL_REGISTER_PTR_PLUS_WORD:
        if extra == None:
          raise InvalidOperand('Extra missing: VAL_REGISTER_PTR_PLUS_WORD')
        operand.type = o_displ
        operand.reg = value - 0x10
        #operand.phrase = self.REGISTER_FAKE_INDEX
        operand.addr = extra
        dbgprint('register_operand VAL_REGISTER_PTR_PLUS_WORD 0x%04x 0x%04x',
            operand.reg, operand.addr)

      elif value in self.VAL_POP_STACK:
        operand.type = o_displ
        operand.reg = self.REGISTER_SP
        #operand.phrase = self.REGISTER_FAKE_INDEX
        operand.addr = 1
        dbgprint('register_operand VAL_POP_STACK 0x%04x 0x%04x',
            operand.reg, operand.addr)

      elif value in self.VAL_PEEK_STACK:
        operand.type = o_phrase
        operand.reg = self.REGISTER_SP
        #operand.phrase = self.REGISTER_FAKE_INDEX
        dbgprint('register_operand VAL_PEEK_STACK 0x%04x', operand.reg)

      elif value in self.VAL_PUSH_STACK:
        operand.type = o_displ
        operand.reg = self.REGISTER_SP
        #operand.phrase = self.REGISTER_FAKE_INDEX
        operand.addr = -1
        dbgprint('register_operand VAL_PUSH_STACK 0x%04x 0x%04x',
            operand.reg, operand.addr)

      elif value in self.VAL_REGISTER_SP:
        operand.type = o_reg
        operand.reg = self.REGISTER_SP
        dbgprint('register_operand VAL_REGISTER_SP 0x%04x', operand.reg)

      elif value in self.VAL_REGISTER_PC:
        operand.type = o_reg
        operand.reg = self.REGISTER_PC
        dbgprint('register_operand VAL_REGISTER_PC 0x%04x', operand.reg)

      elif value in self.VAL_REGISTER_O:
        operand.type = o_reg
        operand.reg = self.REGISTER_O
        dbgprint('register_operand VAL_REGISTER_O 0x%04x', operand.reg)

      elif value in self.VAL_NEXT_WORD_PTR:
        if extra == None:
          raise InvalidOperand('Extra missing: VAL_NEXT_WORD_PTR')
        operand.type = o_mem
        operand.addr = extra
        dbgprint('register_operand VAL_NEXT_WORD_PTR 0x%04x', operand.addr)

      elif value in self.VAL_NEXT_WORD:
        if extra == None:
          raise InvalidOperand('Extra missing: VAL_NEXT_WORD')
        operand.type = o_imm
        operand.value = extra
        dbgprint('register_operand VAL_NEXT_WORD 0x%04x', operand.value)

      elif value in self.VAL_LITERAL:
        operand.type = o_imm
        operand.value = value - 0x20
        dbgprint('register_operand VAL_LITERAL 0x%04x', operand.value)

      else:
        raise InvalidOperand('Invalid operand: %d' % (value,))
      return extra_op_len


    # ======================================================================
    # Processor module callbacks
    # ======================================================================

    def notify_init(self):
      pass
      #self.cvar.inf.mf = True

    def get_frame_retsize(self, func_ea):
        """
        Get size of function return address in bytes
        """
        return 2

    def notify_get_autocmt(self):
        """
        Get instruction comment. 'cmd' describes the instruction in question
        @return: None or the comment string
        """
        if 'cmt' in self.instruc[self.cmd.itype]:
          return self.instruc[self.cmd.itype]['cmt']

    def can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc.
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: bool
        """
        return False

    def is_align_insn(self, ea):
        """
        Is the instruction created only for alignment purposes?
        Returns: number of bytes in the instruction
        """
        return 0

    def notify_newfile(self, filename):
        pass

    def notify_oldfile(self, filename):
        pass

    def header(self):
        """function to produce start of disassembled text"""
        MakeLine('; 0x10c DCPU-16 dissassembly', 0)

    def notify_may_be_func(self, state):
        """
        can a function start here?
        the instruction is in 'cmd'
          arg: state -- autoanalysis phase
            state == 0: creating functions
                  == 1: creating chunks
          returns: probability 0..100
        """
        if self.cmd.ea == 0:
          return 100
        op_obj = self.ntable[self.instruc[self.cmd.itype]['name']]
        if op_obj.name == 'JSR':
          return 90
        return 20

    def emu(self):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'cmd' structure.

        Overrides:
          idaapi.processor_t

        Returns:
          If zero is returned, the kernel will delete the instruction.
        """
        xref_set = False
        op_obj = self.ntable[self.instruc[self.cmd.itype]['name']]
        continue_to_next = self.prev_was_conditional 
        # Xref for SET PC, POP
        if not op_obj.IsNonBasic():
          if (self.cmd[0].type == o_reg and
              self.cmd[0].reg == self.REGISTER_PC and
              self.cmd[1].type in (o_displ, o_phrase) and
              self.cmd[1].reg == self.REGISTER_SP and
              op_obj.name == 'SET'):
            # PUSH/POP
            # Func return. Don't set an xref via xref_set True
            xref_set = True

          # Xref for SET PC, <imm>
          elif (self.cmd[0].reg == self.REGISTER_PC and
              self.cmd[1].type == o_imm and
              op_obj.name == 'SET'):
            ua_add_cref(0, self.cmd[1].value * 2, fl_JF)
            xref_set = True

        else:  # if op_obj.IsNonBasic()
          # Xref for JSR
          if self.cmd[0].type == o_imm and op_obj.name == 'JSR':
            dest_pc = self.cmd[0].value * 2
            add_func(dest_pc, BADADDR)
            ua_add_cref(0, dest_pc, fl_JF)
            xref_set = True
            continue_to_next = True

        if not xref_set or continue_to_next:
          ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

        self.prev_was_conditional = op_obj.con
        return 1

    def outop(self, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text

        self.cmd will be initialized by ana().

        Overrides:
          idaapi.processor_t

        Returns:
          1-ok, 0-operand is hidden.
        """
        optype = op.type

        if optype == o_reg:
          dbgprint('outop o_reg')
          out_register(self.regNames[op.reg])

        elif optype == o_imm:
          dbgprint('outop o_imm')
          OutValue(op, OOFW_IMM | OOFS_IFSIGN)

        elif optype == o_mem:
          dbgprint('outop o_mem')
          out_symbol('[')
          OutValue(op, OOF_ADDR | OOFW_IMM | OOFS_NOSIGN)
          out_symbol(']')

        elif optype in (o_displ, o_phrase):
          dbgprint('outop o_displ/o_phrase')
          if op.reg == self.REGISTER_SP:
            if optype == o_phrase:
              out_keyword('PEEK')
            elif op.addr == 1:
              out_keyword('POP')
            elif op.addr == -1:
              out_keyword('PUSH')
            else:
              raise Error('Bad state for REGISTER_SP display')
          else:
            out_symbol('[')
            out_register(self.regNames[op.reg])
            if optype == o_displ and op.addr != 0:
              dbgprint('outop o_displ')
              OutValue(op, OOF_ADDR | OOFW_IMM | OOF_SIGNED | OOFS_NEEDSIGN)
            out_symbol(']')

        else:
          dbgprint('outop -> False')
          return False

        dbgprint('outop -> True')
        return True

    # Generate text representation of an instruction in 'cmd' structure.
    # This function shouldn't change the database, flags or anything else.
    # All these actions should be performed only by u_emu() function.
    def out(self):
        """Outputs instruction.

        self.cmd will be initialized by ana().

        Overrides:
          idaapi.processor_t
        """
        dbgprint('out')
        op_obj = self.ntable[self.instruc[self.cmd.itype]['name']]

        buf = idaapi.init_output_buffer(1024)
        if self.indent_next:
          out_keyword('  ')
        OutMnem(3)

        # HACK: ua_next_word only returns the low order byte of the word. If
        # IDA is told this CPU uses 16-bits each byte, ua_next_byte skips
        # every other byte and ua_next_word still doesn't work.
        # In the event of a change to PC, the immediate set is in words.
        # Since IDA isn't using 16-bits per byte, the immediate's value doesn't
        # match the instruction's byte address. Detect this and adjust the
        # displayed value of the constant.
        modifies_pc = (self.cmd[0].reg == self.REGISTER_PC)
        if not op_obj.IsNonBasic():
          #out_one_operand(1)
          self.outop(self.cmd[0])
          out_symbol(',')
          out_symbol(' ')

          operand = self.cmd[1]
          if modifies_pc and operand.type == o_imm and op_obj.name == 'SET':
            operand.value *= 2
            self.outop(operand)
            operand.value /= 2
          else:
            #out_one_operand(2)
            self.outop(operand)
        else:
          operand = self.cmd[0]
          if operand.type == o_imm and op_obj.name == 'JSR':
            operand.value *= 2
            self.outop(operand)
            operand.value /= 2
          else:
            self.outop(operand)

        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)
        self.indent_next = op_obj.con
        dbgprint('out ->')

    def ana(self):
        """
        Decodes an instruction into the C global variable 'cmd'

        Overrides:
          idaapi.processor_t
        """

        dbgprint('ana')
        op_length = 2

        # take opcode word
        b = (ua_next_byte() << 8) + ua_next_byte()
        dbgprint('opcode 0x%04x', b)

        # the 4bit opcode, adjusted to support non-basic instructions
        # the first value
        # the second value
        opcode = (b & 0x000F) << 8
        valueA = (b & 0x03f0) >> 4
        valueB = (b & 0xFC00) >> 10
        extraA = None
        extraB = None

        # non-basic instructions?
        non_basic = opcode == 0
        if non_basic:
          dbgprint('non-basic op')
          opcode += valueA
          valueA = valueB
          valueB = None
        if valueB == None:
          dbgprint('op 0x%04x, A 0x%02x, B None', opcode, valueA)
        else:
          dbgprint('op 0x%04x, A 0x%02x, B 0x%02x', opcode, valueA, valueB)

        # opcode supported?
        if opcode not in self.otable:
          dbgprint('ana -> unknown opcode')
          return 0

        # register operands
        try:
          if non_basic:
            op_length += self.register_operand(1, valueA)
          else:
            op_length += self.register_operand(1, valueA)
            op_length += self.register_operand(2, valueB)
        except InvalidOperand:
          dbgprint('ana -> InvalidOperand')
          return 0

        ins = self.otable[opcode]
        self.cmd.itype = ins.itype
        self.cmd.size = op_length
        dbgprint('ana -> %d', op_length)
        return op_length

    def init_instructions(self):
      class idef:
        """
        Internal class that describes an instruction by:
        - instruction id
        - instruction name
        - canonical flags used by IDA
        - conditional modifier instruction indicator
        - instruction comment
        """
        def __init__(self, op, name, cf, con = False, cmt = None):
          self.op = op
          self.name = name
          self.cf  = cf
          self.con = con
          self.cmt = cmt
          self.itype = None

        def ToDict(self):
          new_dict = {'op': self.op, 'name': self.name, 'feature': self.cf}
          if self.cmt:
            new_dict['cmt'] = self.cmt
          return new_dict

        def IsNonBasic(self):
          return not (self.op & 0xFF00)

      # ======================================================================
      # Instructions table (w/ pointer to decoder)
      # ======================================================================
      self.itable = [
          idef(0x0001, 'JSR',   0,        cmt='Does a PUSH of PC and jumps to A'),
          idef(0x0100, 'SET',   CF_CHG1,  cmt='A=B'),
          idef(0x0200, 'ADD',   CF_CHG1,  cmt='A=A+B, O=0x01 on overflow'),
          idef(0x0300, 'SUB',   CF_CHG1,  cmt='A=A-B, O=0xFFFF on underflow'),
          idef(0x0400, 'MUL',   CF_CHG1,  cmt='A=A*B, O=High 16 overflow bits'),
          idef(0x0500, 'DIV',   CF_CHG1,  cmt='A=A/B, O=0 if either A or B == 0, O=(a<<16)/b'),
          idef(0x0600, 'MOD',   CF_CHG1,  cmt='A=A%B'),
          idef(0x0700, 'SHL',   CF_CHG1,  cmt='A=A<<B, O=the bits shifted off'),
          idef(0x0800, 'SHR',   CF_CHG1,  cmt='A=A>>B, O=the bits shifted off'),
          idef(0x0900, 'AND',   CF_CHG1),
          idef(0x0A00, 'BOR',   CF_CHG1),
          idef(0x0B00, 'XOR',   CF_CHG1),
          idef(0x0C00, 'IFE',   0,        con=True),
          idef(0x0D00, 'IFN',   0,        con=True),
          idef(0x0E00, 'IFG',   0,        con=True),
          idef(0x0F00, 'IFB',   0,        con=True),
          ]


      # Now create an instruction table compatible with IDA processor module requirements
      self.otable = {}
      self.ntable = {}
      Instructions = []
      i = 0
      for x in self.itable:
        self.otable[x.op] = x
        self.ntable[x.name] = x
        x.itype = i
        Instructions.append(x.ToDict())
        setattr(self, 'itype_' + x.name, i)
        i += 1

      # icode of the last instruction + 1
      self.instruc_end = len(Instructions) + 1

      # Array of instructions
      self.instruc = Instructions

      # Icode of return instruction. It is ok to give any of possible return
      # instructions
      self.icode_return = 0

    def init_registers(self):
      """This function parses the register table and creates corresponding ireg_XXX constants"""

      # Registers definition
      self.regNames = [
        "A",
        "B",
        "C",
        "X",
        "Y",
        "Z",
        "I",
        "J",
        # Fake index register
        "F",
        # Special registers
        "PC", # Program counter
        "SP", # Stack pointer
        "O",  # Overflow
        # Fake segment registers
        "CS",
        "DS"
      ]

      # Create the ireg_XXXX constants
      for i in xrange(len(self.regNames)):
        setattr(self, 'ireg_' + self.regNames[i], i)

      # Segment register information (use virtual CS and DS registers if your
      # processor doesn't have segment registers):
      self.regFirstSreg = self.ireg_CS
      self.regLastSreg  = self.ireg_DS

      # number of CS register
      self.regCodeSreg = self.ireg_CS

      # number of DS register
      self.regDataSreg = self.ireg_DS

    def __init__(self):
      idaapi.processor_t.__init__(self)
      self.indent_next = False
      self.prev_was_conditional = False
      self.PTRSZ = 2
      self.init_instructions()
      self.init_registers()


def PROCESSOR_ENTRY():
    return dcpu16_processor_t()
