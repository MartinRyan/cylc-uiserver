# -*- coding: utf-8 -*-
# Copyright (C) 2019 NIWA & British Crown (Met Office) & Contributors.
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import re
from subprocess import Popen, PIPE

from services.auth import HubAuthenticated
from tornado.web import authenticated, RequestHandler
from typing import List, Union


class CylcScanHandler(HubAuthenticated, RequestHandler):

    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "x-requested-with")
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.set_header("Content-Type", 'application/json')

    def _parse_suite_line(self, suite_line: bytes) -> Union[dict, None]:
        if suite_line:
            parts = re.split(r"[ :@]", suite_line.decode())
            if len(parts) == 4:
                return {
                    "name": parts[0],
                    "user": parts[1],
                    "host": parts[2],
                    "port": int(parts[3])
                }
        return None

    def _get_suites(self, suite_lines: List[bytes]) -> List[dict]:
        suites = []
        for suite_line in suite_lines:
            suite = self._parse_suite_line(suite_line)
            if suite:
                suites.append(suite)
        return suites

    @authenticated
    def get(self):
        cylc_scan_proc = Popen("cylc scan", shell=True, stdout=PIPE)
        cylc_scan_out = cylc_scan_proc.communicate()[0]

        suite_lines = cylc_scan_out.splitlines()
        suites = self._get_suites(suite_lines)
        self.write(json.dumps(suites))


__all__ = ["CylcScanHandler"]
