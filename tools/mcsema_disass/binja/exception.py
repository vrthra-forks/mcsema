#!/usr/bin/env python

# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Modified from the IDA version to support binja

import binaryninja as binja
from collections import namedtuple
import util
from debug import *
import string

frame_entry = namedtuple('frame_entry', ['cs_start', 'cs_end', 'cs_lp', 'cs_action'])
_FUNC_UNWIND_FRAME_EAS = set()
_FUNC_LSDA_ENTRIES = dict()

_EXCEPTION_BLOCKS_EAS = dict()

DW_EH_PE_ptr       = 0x00
DW_EH_PE_uleb128   = 0x01
DW_EH_PE_udata2    = 0x02
DW_EH_PE_udata4    = 0x03
DW_EH_PE_udata8    = 0x04
DW_EH_PE_signed    = 0x08
DW_EH_PE_sleb128   = 0x09
DW_EH_PE_sdata2    = 0x0A
DW_EH_PE_sdata4    = 0x0B
DW_EH_PE_sdata8    = 0x0C

DW_EH_PE_absptr    = 0x00
DW_EH_PE_pcrel     = 0x10
DW_EH_PE_textrel   = 0x20
DW_EH_PE_datarel   = 0x30
DW_EH_PE_funcrel   = 0x40
DW_EH_PE_aligned   = 0x50
DW_EH_PE_indirect  = 0x80
DW_EH_PE_omit      = 0xFF


class EHBlocks(object):
  def __init__(self, start_ea, end_ea):
    self.start_ea = start_ea
    self.end_ea = end_ea


def sign_extn(x, b):
  m = 1 << (b - 1)
  x = x & ((1 << b) - 1)
  return (x ^ m) - m


def make_array(ea, size):
  if ea is not None and ea != 0:
    flags = idc.GetFlags(ea)
    if not idc.isByte(flags) or idc.ItemSize(ea) != 1:
      idc.MakeUnknown(ea, 1, idc.DOUNK_SIMPLE)
      idc.MakeByte(ea)
    idc.MakeArray(ea, size)


def read_string(bv, ea):
  end = bv.find_next_data(ea, '\x00')
  if end is None:
    return None, ea
  return bv.read(ea, end - ea), end + 1


def read_uleb128(bv, ea):
  return util.read_leb128(bv, ea, False)


def read_sleb128(bv, ea):
  return util.read_leb128(bv, ea, True)


def enc_size(enc):
  """ Read encoding size
  """
  fmt = enc & 0x0F
  if fmt == DW_EH_PE_ptr:
    return bv.address_size
  elif fmt in [DW_EH_PE_sdata2, DW_EH_PE_udata2]:
    return 2
  elif fmt in [DW_EH_PE_sdata4, DW_EH_PE_udata4]:
    return 4
  elif fmt in [DW_EH_PE_sdata8, DW_EH_PE_udata8]:
    return 8
  elif fmt != DW_EH_PE_omit:
    DEBUG("Encoding {0:x} is not of fixed size".format(enc))
  return 0


def read_enc_value(bv, ea, enc):
  """ Read encoded value
  """
  if enc == DW_EH_PE_omit:
    DEBUG("Error in read_enc_val {0:x}".format(ea))
    return None, None

  start = ea
  fmt, mod = enc&0x0F, enc&0x70

  if fmt == DW_EH_PE_ptr:
    val = util.read_addr(bv, ea)
    ea += bv.address_size

  elif fmt in [DW_EH_PE_uleb128, DW_EH_PE_sleb128]:
    val, ea = util.read_leb128(bv, ea, fmt == DW_EH_PE_sleb128)
    # if ea - start > 1:
    #   make_array(start, ea - start)

  elif fmt in [DW_EH_PE_sdata2, DW_EH_PE_udata2]:
    val = util.read_word(bv, ea)
    ea += 2
    if fmt == DW_EH_PE_sdata2:
      val = sign_extn(val, 16)

  elif fmt in [DW_EH_PE_sdata4, DW_EH_PE_udata4]:
    val = util.read_dword(bv, ea)
    ea += 4
    if fmt == DW_EH_PE_sdata4:
      val = sign_extn(val, 32)

  elif fmt in [DW_EH_PE_sdata8, DW_EH_PE_udata8]:
    val = util.read_qword(bv, ea)
    ea += 8
    if fmt == DW_EH_PE_sdata8:
      val = sign_extn(val, 64)

  else:
    DEBUG("{0:x}: don't know how to handle {1:x}".format(start, enc))
    return None, None

  if mod == DW_EH_PE_pcrel:
    if val != 0:
      val += start
      val &= (1 << (8 * bv.address_size)) - 1

  elif mod != DW_EH_PE_absptr:
    DEBUG("{0:x}: don't know how to handle {1:x}".format(start, enc))
    return None, None

  if (enc & DW_EH_PE_indirect) and val != 0:
    # if not idc.isLoaded(val):
    #   DEBUG("{0:x}: dereference invalid pointer {1:x}".format(start, val))
    #   return None, None
    val = util.read_addr(bv, val)

  return val, ea


def _create_frame_entry(start = None, end = None, lp = None, action = None):
    return frame_entry(start, end, lp, action)


def format_lsda_action(bv, action_tbl, type_addr, type_enc, act_id):
  """ Recover the exception actions and type info
  """
  action_list = []
  if action_tbl is None:
    return

  act_ea = action_tbl + act_id - 1
  ar_filter,ea2 = read_enc_value(bv, act_ea, DW_EH_PE_sleb128)
  ar_disp,  ea3 = read_enc_value(bv, ea2, DW_EH_PE_sleb128)

  if ar_filter > 0:
    type_slot = type_addr - ar_filter * enc_size(type_enc)
    type_ea, eatmp = read_enc_value(bv, type_slot, type_enc)
    DEBUG("catch type typeinfo = {:x} {}".format(type_ea, util.find_symbol_name(bv, type_ea)))

  if ar_disp == 0:
    return

  next_ea = ea2 + ar_disp
  next_act = next_ea - act_ea + act_id

  #action_list.append((ar_disp, ar_filter, type_ea))
  #DEBUG("ea {:x}: ar_disp[{}]: {} ({:x})".format(act_ea, act_id, ar_disp, ar_filter))
  #return action_list


def format_lsda_actions(bv, action_tbl, actions, type_addr, type_enc, act_id):
  """ Recover the exception actions and type info
  """
  action_list = []
  if action_tbl is None:
    return

  DEBUG("No of Actions : {0}".format(len(actions)))
  while len(actions):
    act_id = actions.pop()
    act_ea = action_tbl + act_id - 1
    ar_filter,ea2 = read_enc_value(bv, act_ea, DW_EH_PE_sleb128)
    ar_disp,  ea3 = read_enc_value(bv, ea2, DW_EH_PE_sleb128)

    if ar_filter > 0:
      type_slot = type_addr - ar_filter * enc_size(type_enc)
      type_ea, eatmp = read_enc_value(bv, type_slot, type_enc)
      DEBUG("catch type typeinfo = {:x} {} {}".format(type_ea, util.find_symbol_name(bv, type_ea), ar_filter))
      if (ar_disp, ar_filter, type_ea) not in action_list:
        action_list.append((ar_disp, ar_filter, type_ea))

    if ar_disp == 0:
      continue

    next_ea = ea2 + ar_disp
    next_act = next_ea - act_ea + act_id
    actions.append(next_act)

  DEBUG("ea {:x}: ar_disp[{}]: {} ({:x})".format(act_ea, act_id, ar_disp, ar_filter))
  return action_list


def create_block_entries(bv, start_ea, heads):
  # index = 0
  # print 'why', start_ea, heads
  block_set = set()
  for index, entry in enumerate(heads):
    if entry == 0:
      continue

    if index < len(heads) - 1:
      ea = heads[index]
      while heads[index] <= ea < heads[index + 1]:
        isize = bv.get_instruction_length(ea)
        # print ea, isize
        block = EHBlocks(ea, ea + isize)
        ea = ea + isize
        block_set.add(block)
    # index = index + 1

  DEBUG('BLOCKSET: {} {}'.format(len(block_set), block_set))
  _EXCEPTION_BLOCKS_EAS[start_ea] = block_set


def format_lsda(bv, lsda_ptr, start_ea, range = None,  sjlj = False):
  """  Recover the language specific data area
  """
  lsda_entries = set()
  heads = set()
  lpstart_enc, ea = util.read_byte(bv, lsda_ptr), lsda_ptr + 1
  if lpstart_enc != DW_EH_PE_omit:
    lpstart, next_ea = read_enc_value(bv, ea, lpstart_enc)
    ea = next_ea
  else:
    lpstart = start_ea

  # get the type encoding and type address associated with the exception handling blocks
  type_enc, ea = util.read_byte(bv, ea), ea + 1
  type_addr = None

  if type_enc != DW_EH_PE_omit:
    type_off, next_ea = read_enc_value(bv, ea, DW_EH_PE_uleb128)
    type_addr = next_ea + type_off
    ea = next_ea

  cs_enc, next_ea = util.read_byte(bv, ea), ea + 1
  ea = next_ea
  cs_len, next_ea = read_enc_value(bv, ea, DW_EH_PE_uleb128)
  action_tbl = next_ea + cs_len
  ea = next_ea

  i = 0
  actions = []
  action_list = []
  while ea < action_tbl:
    if sjlj:
      cs_lp, next_ea = read_enc_value(bv, ea, DW_EH_PE_uleb128)
      act_ea = next_ea
      cs_action, next_ea = read_enc_value(bv, next_ea, DW_EH_PE_uleb128)
      DEBUG("ea {:x}: cs_lp[{}] = {}".format(ea, i, cs_lp))
      ea = next_ea
    else:
      cs_start, next_ea = read_enc_value(bv, ea, cs_enc)
      cs_start += lpstart
      DEBUG("ea {:x}: cs_start[{}] = {:x}  ({})".format(ea, i, cs_start, util.find_symbol_name(bv, start_ea)))
      ea = next_ea
      heads.add(cs_start)

      cs_len, next_ea = read_enc_value(bv, ea, cs_enc & 0x0F)
      cs_end = cs_start + cs_len
      DEBUG("ea {:x}: cs_len[{:x}] = {} (end = {:x})".format(ea, i, cs_len, cs_start + cs_len))
      ea = next_ea
      heads.add(cs_end)

      cs_lp, next_ea = read_enc_value(bv, ea, cs_enc)
      cs_lp = cs_lp + lpstart if cs_lp != 0 else cs_lp
      act_ea = next_ea
      DEBUG("ea {:x}: cs_lp[{}] = {:x}".format(ea, i, cs_lp))
      ea = next_ea
      heads.add(cs_lp)

      cs_action, next_ea = read_enc_value(bv, ea, DW_EH_PE_uleb128)
      ea = next_ea

      if cs_action != 0:
        actions.append(cs_action)

      DEBUG_PUSH()
      DEBUG("Landing pad for {0:x}..{1:x}".format(cs_start, cs_start + cs_len))
      DEBUG_POP()

    lsda_entries.add(_create_frame_entry(cs_start, cs_start + cs_len, cs_lp, cs_action != 0))
    #lsda_entries.add(_create_frame_entry(cs_start, cs_start + cs_len, cs_lp, cs_action))
    DEBUG("ea {:x}: cs_action[{}] = {}".format(act_ea, i, cs_action))
    i += 1

  #if cs_action != 0:
  action_list = format_lsda_actions(bv, action_tbl, actions, type_addr, type_enc, cs_action)

  create_block_entries(bv, start_ea, sorted(heads))
  _FUNC_LSDA_ENTRIES[start_ea] = (lsda_entries, action_list)


class AugmentationData:
  def __init__(self):
    self.aug_present = False
    self.lsda_encoding = DW_EH_PE_omit
    self.personality_ptr = None
    self.fde_encoding = DW_EH_PE_absptr


class EHRecord:
  def __init__(self):
    self.type = ""
    self.version = None
    self.data = None
    self.aug_string = ""
    self.code_align = None
    self.data_align = None
    self.retn_reg = None


_AUGM_PARAM = dict()

def format_entries(bv, ea):
  """ Check the types of entries CIE/FDE recover them

  Args:
    bv (binja.BinaryView)
    ea (int)
  """
  start_ea = ea
  size, ea = util.read_dword(bv, ea), ea + 4
  if size == 0:
    return None

  end_ea = ea + size
  entry = EHRecord()

  cie_id, ea = util.read_dword(bv, ea), ea + 4
  is_cie = cie_id == 0
  entry.type = ["FDE", "CIE"][is_cie]
  #DEBUG("ea {0:x}: type {1} size {2}".format(start_ea, entry.type, size))

  if is_cie:
    entry.version, ea = util.read_byte(bv, ea), ea + 1
    entry.aug_string, ea = read_string(bv, ea)
    if entry.aug_string is None:
      return end_ea

    entry.code_align, ea = read_uleb128(bv, ea)
    entry.data_align, ea = read_uleb128(bv, ea)
    if entry.version == 1:
      entry.retn_reg, ea = util.read_byte(bv, ea), ea + 1
    else:
      entry.retn_reg, ea = read_uleb128(bv, ea)

    aug_data = AugmentationData()

    if entry.aug_string[:1] == 'z':
      aug_len, ea = read_uleb128(bv, ea)
      aug_data.aug_present = True

      for s in entry.aug_string[1:]:
        if s == 'L':
          aug_data.lsda_encoding, ea = util.read_byte(bv, ea), ea + 1
        elif s == 'P':
          enc, ea = util.read_byte(bv, ea), ea + 1
          aug_data.personality_ptr, ea2 = read_enc_value(bv, ea, enc)
          #DEBUG("ea {0:x}: personality function {1:x}".format(ea, aug_data.personality_ptr))
          ea = ea2
        elif s == 'R':
          aug_data.fde_encoding, ea = util.read_byte(bv, ea), ea + 1
        else:
          #DEBUG("ea {0:x}: unhandled string char {1}".format(ea, s))
          return None

    _AUGM_PARAM[start_ea] = aug_data

  else:
    base_ea = ea - 4
    cie_ea = base_ea - cie_id
    if cie_ea in _AUGM_PARAM:
      aug_data = _AUGM_PARAM[cie_ea]
    else:
      return None

    pc_begin, ea2 = read_enc_value(bv, ea, aug_data.fde_encoding)
    #DEBUG("ea {0:x}: CIE pointer".format(base_ea))
    #DEBUG("ea {0:x}: PC begin={1:x}".format(ea, pc_begin))

    ea = ea2
    range_len, ea2 = read_enc_value(bv, ea, aug_data.fde_encoding & 0x0F)
    #DEBUG("ea {:x}: PC range = {:x} (PC end={:x})".format(ea, range_len, range_len + pc_begin))

    if range_len:
      _FUNC_UNWIND_FRAME_EAS.add((pc_begin, range_len))

    ea = ea2
    if aug_data.aug_present:
      aug_len, ea = read_uleb128(bv, ea)
      if aug_data.lsda_encoding != DW_EH_PE_omit:
        lsda_ptr, ea2 = read_enc_value(bv, ea, aug_data.lsda_encoding)
        #DEBUG("ea {0:x}: LSDA pointer {1:x}".format(ea, lsda_ptr))
        DEBUG_PUSH()
        if lsda_ptr:
          format_lsda(bv, lsda_ptr, pc_begin, range_len, False)
        DEBUG_POP()

  return end_ea


def recover_frame_entries(bv, sec):
  # type: (binja.BinaryView, binja.Section) -> None
  DEBUG("Recover entries from section : {}".format(sec.name))
  ea = sec.start
  while ea is not None and ea < sec.end:
    ea = format_entries(bv, ea)


def recover_exception_table(bv):
  """ Recover the CIE and FDE entries from the segment .eh_frame

  Args:
    bv (binja.BinaryView)
  """
  for sec_name, sec in bv.sections.iteritems():
    if sec_name in ['.eh_frame', '__eh_frame']:
      recover_frame_entries(bv, sec)
      break


def recover_exception_entries(bv, pb_func, func_ea):
  has_unwind_frame = func_ea in _FUNC_LSDA_ENTRIES.keys()
  if has_unwind_frame:
    lsda_entries, action_list = _FUNC_LSDA_ENTRIES[func_ea]

    for entry in lsda_entries:
      pb_eh = pb_func.eh_frame.add()
      pb_eh.func_ea = func_ea
      pb_eh.start_ea = entry.cs_start
      pb_eh.end_ea = entry.cs_end
      pb_eh.lp_ea = entry.cs_lp
      pb_eh.action = entry.cs_action

      for ar_disp, ar_filter, type_ea in action_list:
        pb_ac = pb_eh.ttype.add()
        pb_ac.ea = type_ea
        pb_ac.name = util.find_symbol_name(bv, type_ea)
        pb_ac.size = ar_filter
        pb_ac.is_weak = False
        pb_ac.is_thread_local = False


def fix_function_bounds(min_ea, max_ea):
  for func_ea, range in _FUNC_UNWIND_FRAME_EAS:
    if func_ea == min_ea:
      return func_ea, func_ea + range
  return min_ea, max_ea


def get_exception_landingpad(F, insn_ea):
  has_lp = F.ea in _FUNC_LSDA_ENTRIES.keys()
  if has_lp:
    lsda_entries, action_list = _FUNC_LSDA_ENTRIES[F.ea]
    for entry in lsda_entries:
      if insn_ea >= entry.cs_start and insn_ea < entry.cs_end:
        return entry.cs_lp
  return 0

def is_lp_end(F, insn_ea):
  has_lp = F.ea in _FUNC_LSDA_ENTRIES.keys()
  if has_lp:
    lsda_entries, action_list = _FUNC_LSDA_ENTRIES[F.ea]
    return any(insn_ea == entry.cs_end for entry in lsda_entries)
  return False

def get_exception_chunks(sub_ea):
  has_block = sub_ea in _EXCEPTION_BLOCKS_EAS.keys()
  if has_block:
    block_set = _EXCEPTION_BLOCKS_EAS[sub_ea]
    for block in block_set:
      yield block.start_ea, block.end_ea
