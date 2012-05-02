#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# Copyright (c) 2012 by Delphix. All rights reserved.
#

The vmxnet3s driver is a paravirtualized GLDv3 NIC driver designed to
be used on VMware virtual machines version 7 and later.  This version
of the driver is based on the "stable-8.6.x" branch of the VMware
open-vm-tools which can be obtained from:

http://open-vm-tools.sourceforge.net/

Changes from stable-8.6.x include:

* add support for dladm mtu property
* add support for VLANs
* LSO fix contributed by Michael Tsymbalyuk <mtzaurus@gmail.com>
* enable building in the illumos gate
* enable building with the Sun Studio compiler
* lint cleanup: the driver is lint clean with two categorical
  exceptions for which warnings are disabled in the Makefile

The driver remains in the original C style to facilitate potential
future synchronization with upstream.
