# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBfdAuth(frrtest.TestMultiOut):
    program = "./test_bfd_auth"


TestBfdAuth.exit_cleanly()
