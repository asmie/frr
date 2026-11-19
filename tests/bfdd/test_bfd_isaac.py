# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBfdIsaac(frrtest.TestMultiOut):
    program = "./test_bfd_isaac"


TestBfdIsaac.exit_cleanly()
