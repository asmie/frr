# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestBfdAuthOpt(frrtest.TestMultiOut):
    program = "./test_bfd_auth_opt"


TestBfdAuthOpt.exit_cleanly()
