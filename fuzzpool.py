# Copyright 2015 F-Secure Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You
# may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.


import tempfile
import os
import subprocess
import shutil
import time
import itertools


class FuzzPool:
    '''A generic fuzzed string provider. Provide a directory of valid
    test cases, get a list of fuzz cases in return. Depends on Radamsa.'''

    def __init__(self, radamsa_path):
        # Initialise buffers for fuzzcases
        self.fuzzcases = {}
        self.fuzzcase_iters = {}
        self.valid_cases = {}
        self.valid_cases_iter = {}
        self.radamsa_path = radamsa_path

    def get_next_fuzzcase(self, path):
        """Returns one fuzzcase using the valid-case path provided.
        """

        try:
            return next(self.fuzzcase_iters[path])
        except (StopIteration, KeyError):
            # We did not have any fuzz cases at hand (yet or any more)
            # so we'll run Radamsa and fill the buffers.
            if os.path.isdir(path) is False:
                raise IOError('Valid-case path "%s" is not a directory' % path)
            self.fuzzcases[path] = self.run_fuzzer(path, 500, self.radamsa_path)
            self.fuzzcase_iters[path] = iter(self.fuzzcases[path])
            return next(self.fuzzcase_iters[path])

    def get_valid_case(self, path):
        """Returns one valid case from a valid case directory
        """

        try:
            return next(self.valid_cases_iter[path])
        except (StopIteration, KeyError):
            # We haven't yet read in valid cases
            if os.path.isdir(path) is False:
                raise IOError('Valid-case path "%s" is not a directory' % path)
            self.valid_cases[path] = []
            for filename in os.listdir(path):
                filehandle = open(os.path.join(path, filename), "rb")
                self.valid_cases[path].append(filehandle.read())
            self.valid_cases_iter[path] = itertools.cycle(iter(self.valid_cases[path]))
            return next(self.valid_cases_iter[path])

    def run_fuzzer(self, valid_case_directory, no_of_fuzzcases, radamsacmd):
        """Run Radamsa on a set of valid values

        :param valuelist: Valid cases to feed to Radamsa
        :param no_of_fuzzcases: Number of fuzz cases to generate
        :param radamsacmd: Command to run Radamsa
        :return:
        """

        # Radamsa is a file-based fuzzer so it outputs into a directory
        fuzz_case_directory = tempfile.mkdtemp()

        if no_of_fuzzcases < 1:
            no_of_fuzzcases = 1

        print("{}:Generating {} new fuzz cases for path '{}'".format(time.asctime(time.gmtime()), no_of_fuzzcases, valid_case_directory))

        # Run Radamsa
        try:
            subprocess.check_call(
                [radamsacmd, "-o", os.path.join(fuzz_case_directory, "%n.fuzz"), "-n",
                 str(no_of_fuzzcases), "-r", valid_case_directory])
        except subprocess.CalledProcessError as error:
            raise error

        # Read the fuzz cases from the output directory and return as list
        fuzzlist = []
        for filename in os.listdir(fuzz_case_directory):
            filehandle = open(os.path.join(fuzz_case_directory, filename), "rb")
            fuzzlist.append(filehandle.read())
        shutil.rmtree(fuzz_case_directory)
        return fuzzlist
