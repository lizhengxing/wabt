#!/usr/bin/env python
#
# Copyright 2017 WebAssembly Community Group participants
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
#

import argparse
try:
  from cStringIO import StringIO
except ImportError:
  from io import StringIO
import json
import os
import struct
import subprocess
import sys

import find_exe
import utils
from utils import Error

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

F32_INF = 0x7f800000
F32_NEG_INF = 0xff800000
F32_NEG_ZERO = 0x80000000
F32_SIGN_BIT = F32_NEG_ZERO
F32_SIG_MASK = 0x7fffff
F32_QUIET_NAN = 0x7fc00000
F32_QUIET_NAN_TAG = 0x400000
F64_INF = 0x7ff0000000000000
F64_NEG_INF = 0xfff0000000000000
F64_NEG_ZERO = 0x8000000000000000
F64_SIGN_BIT = F64_NEG_ZERO
F64_SIG_MASK = 0xfffffffffffff
F64_QUIET_NAN = 0x7ff8000000000000
F64_QUIET_NAN_TAG = 0x8000000000000


def I32ToC(value):
  return '%su' % value


def I64ToC(value):
  return '%sull' % value


def IsNaNF32(f32_bits):
  return (F32_INF < f32_bits < F32_NEG_ZERO) or (f32_bits > F32_NEG_INF)


def IsNaNF64(f64_bits):
  return (F64_INF < f64_bits < F64_NEG_ZERO) or (f64_bits > F64_NEG_INF)


def ReinterpretF32(f32_bits):
  return struct.unpack('<f', struct.pack('<I', f32_bits))[0]


def ReinterpretF64(f64_bits):
  return struct.unpack('<d', struct.pack('<Q', f64_bits))[0]


def F32ToC(f32_bits):
  if f32_bits == F32_INF:
    return 'INFINITY'
  elif f32_bits == F32_NEG_INF:
    return '-INFINITY'
  elif IsNaNF32(f32_bits):
    return 'NAN /*0x%08x*/' % f32_bits  # TODO(binji): specific NAN bit patterns
  else:
    return '%sf' % repr(ReinterpretF32(f32_bits))


def F64ToC(f64_bits):
  if f64_bits == F64_INF:
    return 'INFINITY'
  elif f64_bits == F64_NEG_INF:
    return '-INFINITY'
  elif IsNaNF64(f64_bits):
    return 'NAN /*0x%016x*/' % f64_bits  # TODO(binji): specific NAN bit patterns
  else:
    # Use repr to get full precision
    return repr(ReinterpretF64(f64_bits))


def MangleName(s):
  result = 'Z_'
  for c in s:
    if (c.isalnum() and c != 'Z') or c == '_':
      result += c
    else:
      result += 'Z%02X' % ord(c)
  return result


class CWriter(object):

  def __init__(self, base_dir, spec_json, out_file):
    self.base_dir = base_dir
    self.source_filename = os.path.basename(spec_json['source_filename'])
    self.commands = spec_json['commands']
    self.out_file = out_file
    self.module_idx = 0

  def Write(self):
    for command in self.commands:
      self._WriteCommand(command)

  def _WriteFileAndLine(self, command):
    self.out_file.write('// %s:%d\n' % (self.source_filename, command['line']))

  def _WriteCommand(self, command):
    command_funcs = {
        'module': self._WriteModuleCommand,
        'action': self._WriteActionCommand,
        'register': self._WriteRegisterCommand,
        # 'assert_malformed': None,
        # 'assert_invalid': None,
        # 'assert_unlinkable': None,
        # 'assert_uninstantiable': None,
        'assert_return': self._WriteAssertReturnCommand,
        'assert_return_canonical_nan': self._WriteAssertReturnNanCommand,
        'assert_return_arithmetic_nan': self._WriteAssertReturnNanCommand,
        'assert_trap': self._WriteAssertActionCommand,
        'assert_exhaustion': self._WriteAssertActionCommand,
    }

    func = command_funcs.get(command['type'])
    if func is not None:
      self._WriteFileAndLine(command)
      func(command)
      self.out_file.write('\n')

  def _ModuleIdxName(self):
    return '$%d' % self.module_idx

  def _WriteModuleCommand(self, command):
    self.module_idx += 1
    idx_name = self._ModuleIdxName()

    # self.out_file.write('let %s = instance("%s");\n' %
    #                     (idx_name, self._Module(command['filename'])))
    # if 'name' in command:
    #   self.out_file.write('let %s = %s;\n' % (command['name'], idx_name))

  def _WriteActionCommand(self, command):
    self.out_file.write('%s;\n' % self._Action(command['action']))

  def _WriteRegisterCommand(self, command):
    # TODO
    pass

  def _WriteAssertReturnCommand(self, command):
    expected = command['expected']
    if len(expected) == 1:
      assert_map = {
        'i32': 'ASSERT_RETURN_I32',
        'f32': 'ASSERT_RETURN_F32',
        'i64': 'ASSERT_RETURN_I64',
        'f64': 'ASSERT_RETURN_F64',
      }

      type_ = expected[0]['type']
      assert_macro = assert_map[type_]
      self.out_file.write('%s(%s, %s);\n' %
                          (assert_macro,
                           self._Action(command['action']),
                           self._ConstantList(expected)))
    elif len(expected) == 0:
      self._WriteAssertActionCommand(command)
    else:
      raise Error('Unexpected result with multiple values: %s' % expected)

  def _WriteAssertReturnNanCommand(self, command):
    assert_map = {
      ('assert_return_canonical_nan', 'f32'): 'ASSERT_RETURN_CANONICAL_NAN_F32',
      ('assert_return_canonical_nan', 'f64'): 'ASSERT_RETURN_CANONICAL_NAN_F64',
      ('assert_return_arithmetic_nan', 'f32'): 'ASSERT_RETURN_ARITHMETIC_NAN_F32',
      ('assert_return_arithmetic_nan', 'f64'): 'ASSERT_RETURN_ARITHMETIC_NAN_F64',
    }

    expected = command['expected']
    type_ = expected[0]['type']
    assert_macro = assert_map[(command['type'], type_)]

    self.out_file.write('%s(%s);\n' % (assert_macro,
                                       self._Action(command['action'])))

  def _WriteAssertActionCommand(self, command):
    self.out_file.write('%s(() => %s);\n' % (command['type'],
                                             self._Action(command['action'])))

  def _Module(self, filename):
    with open(os.path.join(self.base_dir, filename), 'rb') as wasm_file:
      return ''.join('\\x%02x' % c for c in bytearray(wasm_file.read()))

  def _Constant(self, const):
    type_ = const['type']
    value = int(const['value'])
    if type_ == 'i32':
      return I32ToC(value)
    elif type_ == 'i64':
      return I64ToC(value)
    elif type_ == 'f32':
      return F32ToC(value)
    elif type_ == 'f64':
      return F64ToC(value)
    else:
      assert False

  def _ConstantList(self, consts):
    return ', '.join(self._Constant(const) for const in consts)

  def _Action(self, action):
    type_ = action['type']
    # TODO(binji): figure out how to do multiple instances.
    # module = action.get('module', self._ModuleIdxName())
    field = MangleName(action['field'])
    if type_ == 'invoke':
      return '%s(%s)' % (field, self._ConstantList(action.get('args', [])))
    elif type_ == 'get':
      return field
    else:
      raise Error('Unexpected action type: %s' % type_)


def main(args):
  parser = argparse.ArgumentParser()
  parser.add_argument('-o', '--out-dir', metavar='PATH',
                      help='output directory for files.')
  parser.add_argument('--bindir', metavar='PATH',
                      default=find_exe.GetDefaultPath(),
                      help='directory to search for all executables.')
  parser.add_argument('--cc', metavar='PATH',
                      help='the path to the C compiler', default='cc')
  parser.add_argument('--cflags', metavar='FLAGS',
                      help='additional flags for C compiler.',
                      action='append', default=[])
  parser.add_argument('-v', '--verbose', help='print more diagnotic messages.',
                      action='store_true')
  parser.add_argument('--no-error-cmdline',
                      help='don\'t display the subprocess\'s commandline when'
                      + ' an error occurs', dest='error_cmdline',
                      action='store_false')
  parser.add_argument('-p', '--print-cmd',
                      help='print the commands that are run.',
                      action='store_true')
  parser.add_argument('file', help='wast file.')
  options = parser.parse_args(args)

  with utils.TempDirectory(options.out_dir, 'run-spec-wasm2c-') as out_dir:
    wast2json = utils.Executable(
        find_exe.GetWast2JsonExecutable(options.bindir),
        error_cmdline=options.error_cmdline)
    wast2json.AppendOptionalArgs({'-v': options.verbose})

    # wasm2c = utils.Executable(
    #     find_exe.GetWasm2CExecutable(options.bindir),
    #     error_cmdline=options.error_cmdline)

    # cc = utils.Executable(options.cc, *options.cflags)

    json_file_path = utils.ChangeDir(
        utils.ChangeExt(options.file, '.json'), out_dir)
    wast2json.RunWithArgs(options.file, '-o', json_file_path)

    with open(json_file_path) as json_file:
      spec_json = json.load(json_file)

    all_commands = spec_json['commands']
    output = StringIO()
    # if options.prefix:
    #   with open(options.prefix) as prefix_file:
    #     output.write(prefix_file.read())
    #     output.write('\n')

    CWriter(out_dir, spec_json, output).Write()

  # if options.output:
  #   out_file = open(options.output, 'w')
  # else:
  out_file = sys.stdout

  try:
    out_file.write(output.getvalue())
  finally:
    out_file.close()

  return 0


if __name__ == '__main__':
  try:
    sys.exit(main(sys.argv[1:]))
  except Error as e:
    sys.stderr.write(str(e) + '\n')
    sys.exit(1)
