/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * This measures metrics that relate to the performance of the ZIL.
 *
 * The following fuctions are all instrumented: "zil_commit",
 * "zil_commit_writer", and "zil_flush_vdevs". For each function, the
 * number of times each function is called is tracked, as well as the
 * average latency for function, and a histogram of the latencies for
 * each function.
 *
 * Additionally, these same measurements are collected for the region of
 * code in the "zil_commit_writer" function that is deliniated by the
 * "zil-cw1" and "zil-cw2" static DTrace probes.
 *
 * Lastly, information about the average number of ZIL blocks and ZIL
 * records is tracked for each call to "zil_commit_writer".
 */

#pragma D option aggsortkey
#pragma D option quiet

BEGIN
{
	@c["zil_cw"] = count();
	@a["zil_cw"] = avg(0);
	@h["zil_cw"] = quantize(0);

	@c["zil_commit"] = count();
	@a["zil_commit"] = avg(0);
	@h["zil_commit"] = quantize(0);

	@c["zil_commit_writer"] = count();
	@a["zil_commit_writer"] = avg(0);
	@h["zil_commit_writer"] = quantize(0);

	@c["zil_flush_vdevs"] = count();
	@a["zil_flush_vdevs"] = avg(0);
	@h["zil_flush_vdevs"] = quantize(0);

	@a["zil_blocks"] = avg(0);
	@h["zil_blocks"] = quantize(0);

	@a["zil_records"] = avg(0);
	@h["zil_records"] = quantize(0);

	clear(@c);
	clear(@a);
	clear(@h);
}

fbt:zfs:zil_commit:return
{
	@c[probefunc] = count();
	@a[probefunc] = avg(entry->elapsed);
	@h[probefunc] = quantize(entry->elapsed);
}

fbt:zfs:zil_commit_writer:return
/ callers["zil_commit"] /
{
	@c[probefunc] = count();
	@a[probefunc] = avg(entry->elapsed);
	@h[probefunc] = quantize(entry->elapsed);
}

fbt:zfs:zil_flush_vdevs:return
/ callers["zil_commit_writer"] /
{
	@c[probefunc] = count();
	@a[probefunc] = avg(entry->elapsed);
	@h[probefunc] = quantize(entry->elapsed);
}

fbt:zfs:zio_flush:return
/ callers["zil_flush_vdevs"] /
{
	@c[probefunc] = count();
	@a[probefunc] = avg(entry->elapsed);
	@h[probefunc] = quantize(entry->elapsed);

	this->path = stringof(entry->args[1]->vdev_path);
	@c_zio_flush[this->path] = count();
	@a_zio_flush[this->path] = avg(entry->elapsed);
	@h_zio_flush[this->path] = quantize(entry->elapsed);
}

sdt:zfs::zil-cw1
/ callers["zil_commit_writer"] /
{
	self->zil_cw = timestamp;
	self->zil_records = 0;
	self->zil_blocks = 0;
}

fbt:zfs:zil_lwb_commit:entry
/ self->zil_cw != 0 /
{
	self->zil_records++;
}

fbt:zfs:zil_lwb_write_start:entry
/ self->zil_cw != 0 /
{
	self->zil_blocks++;
}

sdt:zfs::zil-cw2
/ self->zil_cw != 0 /
{
	@c["zil_cw"] = count();
	this->elapsed = timestamp - self->zil_cw;
	@a["zil_cw"] = avg(this->elapsed);
	@h["zil_cw"] = quantize(this->elapsed);
	self->zil_cw = 0;

	@a["zil_blocks"] = avg(self->zil_blocks);
	@h["zil_blocks"] = quantize(self->zil_blocks);
	self->zil_blocks = 0;

	@a["zil_records"] = avg(self->zil_records);
	@h["zil_records"] = quantize(self->zil_records);
	self->zil_records = 0;
}

tick-$2s
{
	printf("%u\n", `time);
	printa("counts_%-21s %@u\n", @c);
	printa("counts_zio_flush_%-10s %@u\n", @c_zio_flush);
	printa("avgs_%-21s %@u\n", @a);
	printa("avgs_zio_flush_%-10s %@u\n", @a_zio_flush);
	printa("histograms_%-21s %@u\n", @h);
	printa("histograms_zio_flush_%-10s %@u\n", @h_zio_flush);

	clear(@c);
	clear(@a);
	clear(@h);

	clear(@c_zio_flush);
	clear(@a_zio_flush);
	clear(@h_zio_flush);
}

ERROR
{
	trace(arg1);
	trace(arg2);
	trace(arg3);
	trace(arg4);
	trace(arg5);
}
