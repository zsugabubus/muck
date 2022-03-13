#include "assert_utils.h"
#include <errno.h>
#include <stdarg.h>

#include <libavutil/channel_layout.h>

#include "fdata.h"
#include "player.h"
#include "playlist.h"

void
fdata_reset(FileData *fdata, size_t urlsz)
{
	for (enum Metadata i = 0; i < M_NB; ++i)
		fdata->f.metadata[i] = 0;
	fdata->urlsz = urlsz;
	fdata->sz = fdata->urlsz;
}

void
fdata_reset_with_url(FileData *fdata, char const *url)
{
	fdata_reset(fdata, strlen(url) + 1 /* NUL */);
}

int
fdata_append(FileData *fdata, enum Metadata m, char const *value)
{
	size_t old_fdata_size = fdata->sz;
	int any = !!fdata->f.metadata[m];

	if (!any) {
		fdata->f.metadata[m] = fdata->sz;
	} else {
		/* Under normal conditions the same kind of metadata is written
		 * continously except M_*_totals.
		 *
		 * This limitation could be overcome by copying fdata.buf
		 * around to being able to append to the existing metadata it. */
		switch (m) {
		case M_track_total:
		case M_disc_total:
			return 0;

		default:
			break;
		}

		fdata->buf[fdata->sz - 1] = ';';
	}

	char pc = '\0';
	for (;; ++value) {
		if (sizeof fdata->buf <= fdata->sz)
			return -1;
		if (!*value)
			break;
		char c = (unsigned char)*value < ' ' ? ' ' : *value;
		switch (m) {
		default:
			/* Nothing. */
			break;

		case M_track:
		case M_disc:
			if ('/' == c)
				goto eos;
			/* FALLTHROUGH */
		case M_track_total:
		case M_disc_total:
		case M_date:
		case M_bpm:
			/* Trim leading zeros. */
			if (!pc && '0' == c)
				continue;
		}
		if ((!pc || ' ' == pc) && ' ' == c)
			continue;
		fdata->buf[fdata->sz++] = c;
		pc = c;
	}
eos:
	fdata->sz -= ' ' == pc;
	if (old_fdata_size == fdata->sz) {
	rollback:
		if (!any)
			fdata->f.metadata[m] = 0;
		else
			fdata->buf[old_fdata_size - 1 /* ; */] = '\0';
		return 0;
	}
	fdata->buf[fdata->sz++] = '\0';

	if (M_date == m &&
	    fdata->sz - old_fdata_size == 8 + 1 /* NUL */)
	{
		if (sizeof fdata->buf <= fdata->sz + 2)
			return -1;

		/*-    543210
		 * 11112233Z
		 * 1111-22-33Z
		 *          ^*/
		memmove(&fdata->buf[fdata->sz - 1], &fdata->buf[fdata->sz - 3], 3);
		memmove(&fdata->buf[fdata->sz - 4], &fdata->buf[fdata->sz - 5], 2);
		fdata->buf[fdata->sz - 2] = '-';
		fdata->buf[fdata->sz - 5] = '-';
		fdata->sz += 2;
	}

	/* Use most precise date. */
	if (M_date == m && any) {
		size_t old_size = old_fdata_size - fdata->f.metadata[m];
		if (old_size < fdata->sz - old_fdata_size) {
			memmove(&fdata->buf[fdata->f.metadata[m]],
					&fdata->buf[old_fdata_size],
					fdata->sz - old_fdata_size);
			fdata->sz -= old_size;
		} else {
			goto rollback;
		}
	}

	if (*value) {
		assert(M_track == m || M_disc == m);
		assert('/' == *value);
		enum Metadata totalm = M_disc == m
			? M_disc_total
			: M_track_total;
		return fdata_append(fdata, totalm, value + 1);
	}

	return 0;
}

int
fdata_writef(FileData *fdata, enum Metadata m, char const *format, ...)
{
	va_list ap;

	va_start(ap, format);
	size_t rem = sizeof fdata->buf - fdata->sz;
	int n = vsnprintf(fdata->buf + fdata->sz, rem, format, ap);
	va_end(ap);

	if (rem <= (size_t)n)
		return -ENOSPC;
	if (!n)
		return 0;

	fdata->f.metadata[m] = fdata->sz;
	fdata->sz += n + 1 /* NUL */;

	return 0;
}

int
fdata_write_basic(FileData *fdata, PlayerMetadataEvent const *e)
{
	int rc;

	if (e->codec_name) {
		char buf[128];
		av_get_channel_layout_string(buf, sizeof buf,
				e->channels,
				e->channel_layout);
		rc = fdata_writef(fdata, M_codec,
				"%s-%s-%d",
				e->codec_name,
				buf,
				e->sample_rate / 1000);
		if (rc < 0)
			return rc;
	}

	if (e->cover_codec_id) {
		rc = fdata_writef(fdata, M_cover_codec,
				"%s-%d",
				avcodec_get_name(e->cover_codec_id),
				e->cover_width);
		if (rc < 0)
			return rc;
	}

	/* Preserve. */
	if (e->f->metadata[M_comment]) {
		int rc = fdata_writef(fdata, M_comment,
				"%s",
				e->f->url + e->f->metadata[M_comment]);
		if (rc < 0)
			return rc;
	}

	return 0;
}

int
fdata_write_date(FileData *fdata, enum Metadata m, time_t time)
{
	size_t size = sizeof fdata->buf - fdata->sz;
	int n = strftime(fdata->buf + fdata->sz, size, "%F", gmtime(&time));
	if (!n)
		return -ENOSPC;

	fdata->f.metadata[m] = fdata->sz;
	fdata->buf[fdata->sz + n] = '\0';
	fdata->sz += n + 1 /* NUL */;

	return 0;
}

int
fdata_save(FileData const *fdata, File *f)
{
	Playlist *playlist = file_get_playlist(f);

	for (enum Metadata i = 0; i < M_NB; ++i)
		if (!!fdata->f.metadata[i] != !!f->metadata[i] ||
		    (fdata->f.metadata[i] &&
		     strcmp(fdata->buf + fdata->f.metadata[i], f->url + f->metadata[i])))
			goto changed;
	return 0;
changed:

	void *p = malloc(fdata->sz);
	if (!p)
		return -ENOMEM;

	playlist->modified = 1;

	memcpy(p, f->url, fdata->urlsz);
	memcpy(p + fdata->urlsz, fdata->buf + fdata->urlsz, fdata->sz - fdata->urlsz);

	free(f->url);
	f->url = p;

	memcpy(f->metadata, fdata->f.metadata, sizeof f->metadata);

	return 0;
}

