#!/usr/bin/env python3.3
# This file is part of jmmhasher.
# Copyright (C) 2014 Joshua Harley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file LICENSE.txt. If not, see
# http://www.gnu.org/licenses/.

"""Quick and dirty test implementation for the libhasher dynamic library."""

from ctypes import Structure, Union, CFUNCTYPE, POINTER, c_int32, \
                   c_ubyte, c_uint64, c_wchar_p, cdll
from binascii import hexlify
import os
import sys

class HashResults(Structure):
    """Simple structure for accessing the results of the hashing operation using
       aligned access rather than byte splicing."""
    _fields_ = [
        ("ed2k", c_ubyte * 16),
        ("crc32", c_ubyte * 4),
        ("md5", c_ubyte * 16),
        ("sha1", c_ubyte * 20)]

class HashResultsUnion(Union):
    """Union of the HashResults and the actual 56-byte array. Technically this
       class isn't needed and the HashResults could be merged into the
       HashRequest directly but I wanted to make the relationship explicit."""
    _fields_ = [
        ("raw", c_ubyte * 56),
        ("results", HashResults)]

class HashRequest(Structure):
    """Actual request class used to request the hasher to process the given
       filename using the hashes identified in the options."""
    _anonymous_ = ("results",)
    _fields_ = [
        ("tag", c_int32),
        ("options", c_int32),
        ("filename", c_wchar_p),
        ("results", HashResultsUnion)]

def hash_progress_callback(tag, progress):
    """Dummy callback to ensure it works."""
    return 0

# Define the prototypes that make up the function and callback.
HashProgressCallbackPrototype = CFUNCTYPE(c_int32, c_int32, c_uint64)
HashSyncIOPrototype = CFUNCTYPE(c_int32, POINTER(HashRequest),
    HashProgressCallbackPrototype)

# Find the library (which is expected to be next to the script) and load it.
libpath = "{0}/libhasher.dylib".format(os.path.dirname(os.path.realpath(__file__)))
libhasher = cdll.LoadLibrary(libpath)

# Create a reference to the exported HashFileWithSyncIO function with the the
# parameter names and types defined.
params = ((1, "request"), (1, "callback"))
HashFileWithSyncIO = HashSyncIOPrototype(("HashFileWithSyncIO", libhasher), params)

# Build our actual request, set the path to a file we got from the command line
# and request the ED2k hash.
request = HashRequest()
request.filename = sys.argv[1]
request.options = 0x01
request.tag = 1

# Create a reference to our callback method.
callback = HashProgressCallbackPrototype(hash_progress_callback)

# Finally, hash the file and print the result.
print(HashFileWithSyncIO(request, callback))
print(hexlify(request.results.ed2k))
