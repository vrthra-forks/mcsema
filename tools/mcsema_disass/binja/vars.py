# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import binaryninja as binja
from binaryninja.enums import (
  SymbolType, TypeClass, InstructionTextTokenType,
  LowLevelILOperation
)

import CFG_pb2
import logging
import util
from debug import *

log = logging.getLogger(util.LOGNAME)


def recover_globals(bv, pb_mod, gvars_file):
  if gvars_file is None:
    return

  log.debug('Recovering globals from %s', gvars_file)
  GM = CFG_pb2.Module()
  GM.ParseFromString(gvars_file.read())
  for gvar in GM.global_vars:
    pb_gvar = pb_mod.global_vars.add()
    pb_gvar.ea = gvar.ea
    pb_gvar.name = gvar.name
    pb_gvar.size = gvar.size


def recover_stack_vars(pb_func, func, var_refs):
  """
  Args:
    pb_func (CFG_pb2.Function)
    func (binaryninja.Function)
    var_refs (dict): map of all var references in the form {var_name => [(addr, off), ...]}
  """
  # Go through all variables on the stack (in order of storage)
  stack_vars = sorted(func.stack_layout, key=lambda var: var.storage)
  for i, svar in enumerate(stack_vars):
    pb_svar = pb_func.stack_vars.add()
    pb_svar.name = svar.name
    pb_svar.sp_offset = svar.storage

    # Var types in binja don't account for arrays
    # Estimate size based on the offset of the next variable
    if svar is not stack_vars[-1]:
      pb_svar.size = stack_vars[i + 1].storage - svar.storage
    else:
      # Edge case for the last variable, the offset is the size
      pb_svar.size = svar.storage

    # Add all references to this variable
    for addr, off in var_refs[svar.name]:
      pb_svref = pb_svar.ref_eas.add()
      pb_svref.inst_ea = addr
      pb_svref.offset = off - svar.storage


def _sp_name(bv):
  return bv.arch.stack_pointer


def _bp_name(bv):
  # TODO(krx): this is currently specific to x86/amd64
  return 'rbp' if _sp_name(bv) == 'rsp' else 'ebp'


def _find_var_name(inst):
  for tok in inst.tokens:
    if tok.type == InstructionTextTokenType.LocalVariableToken:
      return tok.text
  return None


def _is_moving_sp(bv, il):
  if il.operation == LowLevelILOperation.LLIL_SET_REG and \
     il.src.operation in [LowLevelILOperation.LLIL_ADD, LowLevelILOperation.LLIL_SUB]:
    dst = il.dest.name
    src = il.src.left.src.name
    return dst == src == _sp_name(bv)
  return False


def find_stack_var_refs(bv, inst, il, var_refs):
  """ Attempts to find references to a stack variable in a given instruction
  Args:
    bv (binaryninja.BinaryView)
    inst (binaryninja.DisassemblyTextLine)
    il (binaryninja.LowLevelILInstruction)
    var_refs (dict): map of currently known var references in the form {var_name => [(addr, off), ...]}
  """
  # Ignore instructions where we just add/sub sp
  if _is_moving_sp(bv, il):
    return

  # Find a local var being referenced here
  var_name = _find_var_name(inst)
  if var_name is None:
    return

  # Pull out info about the phrase in this instruction
  reg = util.search_phrase_reg(il)
  off = util.search_displ_base(il) or 0

  # If this is accessing a local var, save the ref info
  if reg in [_sp_name(bv), _bp_name(bv)]:
    var_refs[var_name].append((il.address, off))
