#include "assert_utils.h"
#include "atomic_utils.h"
#include "compat/pthread.h"
#include "math_utils.h"
#include "stdio_utils.h"
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libavcodec/avcodec.h>
#include <libavdevice/avdevice.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavformat/avformat.h>
#include <libavutil/frame.h>

#include "birdlock.h"
#include "config.h"
#include "env.h"
#include "player.h"
#include "playlist.h"
#include "tui.h"

#if HAVE___BUILTIN_EXPECT
# define likely(x) __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#else
# define likely(x) x
# define unlikely(x) x
#endif

#define PLAYER_STREAM_INITIALIZER { 0 }

typedef struct {
	AVFormatContext *format_ctx;
	AVCodecContext *codec_ctx;
	AVStream *audio;
	int header_written;
} PlayerStream;

#define PLAYER_SEEK_EVENT_INITIALIZER { \
	.dirfd = -1, \
	.whence = SEEK_CUR, \
	.ts = 0, \
}

typedef struct {
	File *f;
	int dirfd;
	char *url;
	enum FileType type;
	unsigned track;
	int whence;
	int64_t ts;
} PlayerSeekEvent;

#define PLAYER_INPUT_INITIALIZER { \
	.s = PLAYER_STREAM_INITIALIZER, \
	.fd = -1, \
	.seek_event = { \
		PLAYER_SEEK_EVENT_INITIALIZER, \
		PLAYER_SEEK_EVENT_INITIALIZER, \
	}, \
	.metadata_event = { \
		PLAYER_METADATA_EVENT_INITIALIZER, \
		PLAYER_METADATA_EVENT_INITIALIZER, \
	}, \
}

typedef struct {
	PlayerStream s;
	AVStream *cover_front;
	int fd;
	unsigned ntracks;
	File *f; /* File source of events. */

	/* All other file references must be treated opaque. Only this single
	 * reference is maintaned by the outside world and ensured that is
	 * surely alive. */
	File *seek_f;

	PlayerSeekEvent seek_event[2];
	BirdLock seek_lock;
	PlayerMetadataEvent metadata_event[2];
	BirdLock metadata_lock;
} PlayerInput;

#define PLAYER_CONFIGURE_EVENT_INITIALIZER { \
	.last_frame_format = AV_SAMPLE_FMT_NONE, \
}

typedef struct {
	File *f;
	char *format_name;
	char *filename;
	char *codec_name;
	char *graph_descr;

	AVCodec const *codec;
	int native_codec;
	enum AVSampleFormat last_frame_format;
} PlayerConfigureEvent;

#define PLAYER_STREAM_INFO_INITIALIZER { \
	.lock = BIRDLOCK_INITIALIZER, \
}

typedef struct {
	BirdLock lock;
	char buf[2][128];
} PlayerStreamInfo;

#define THREAD_SIGNAL_INITIALIZER { \
	.cond = PTHREAD_COND_INITIALIZER, \
	.lock = PTHREAD_MUTEX_INITIALIZER, \
	.cvar = 0, \
}

typedef struct {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int cvar;
} ThreadSignal;

static pthread_t source_thread, sink_thread;
static ThreadSignal source_signal = THREAD_SIGNAL_INITIALIZER;
static ThreadSignal sink_signal = THREAD_SIGNAL_INITIALIZER;
#if CONFIG_VALGRIND
static int threads_inited;
static atomic_uchar ALIGNED_ATOMIC terminate;
#endif

/**
 * What is being buffered.
 */
static int64_t _Atomic ALIGNED_ATOMIC buffer_bytes;
static int64_t _Atomic ALIGNED_ATOMIC buffer_bytes_max = 8 /* MB */ << 20;
static int64_t _Atomic ALIGNED_ATOMIC buffer_low; /**< When to wake up producer for more frames. */
static int64_t const BUFFER_EOF_LOW = 128 << 10;

/**
 * Producer buffer.
 *
 * Making it non-resizable simplifies implementation.
 */
static AVFrame *buffer[UINT16_MAX + 1];
static uint16_t _Atomic ALIGNED_ATOMIC buffer_head, buffer_tail;
/**
 * buffer_reap..buffer_head: Maybe alloced, reusable frames.
 * buffer_tail..buffer_reap: NULLs.
 */
static uint16_t buffer_reap;

static int64_t _Atomic ALIGNED_ATOMIC cur_pts, cur_duration;
static atomic_uchar ALIGNED_ATOMIC paused;

static PlayerInput in = PLAYER_INPUT_INITIALIZER;
static PlayerStream out = PLAYER_STREAM_INITIALIZER;

static AVFilterGraph *graph;
static AVFilterContext *buffer_ctx, *buffersink_ctx;
static atomic_int ALIGNED_ATOMIC volume = 100; /**< Desired volume. */
static int graph_volume_volume; /**< Configured state of [volume]volume= */

static PlayerStreamInfo source_info = PLAYER_STREAM_INFO_INITIALIZER;
static PlayerStreamInfo sink_info = PLAYER_STREAM_INFO_INITIALIZER;

static BirdLock configure_lock = BIRDLOCK_INITIALIZER;
static PlayerConfigureEvent configure_event[2] = {
	PLAYER_CONFIGURE_EVENT_INITIALIZER,
	PLAYER_CONFIGURE_EVENT_INITIALIZER,
};

static void
player_libav_log_cb(void *ctx, int level, char const *format, va_list ap)
{
	(void)ctx;

	if (av_log_get_level() < level)
		return;

	vfprintf(stderr, format, ap);
}

static void
tui_msg_averror(char const *msg, int err)
{
	char error_buf[AV_ERROR_MAX_STRING_SIZE];
	av_make_error_string(error_buf, sizeof error_buf, err);
	tui_msgf("%s: %s", msg, error_buf);
}

static void
player_signal(ThreadSignal *tsig)
{
	xassert(!pthread_mutex_lock(&tsig->lock));
	tsig->cvar = 1;
	xassert(!pthread_cond_broadcast(&tsig->cond));
	xassert(!pthread_mutex_unlock(&tsig->lock));
}

static void
player_wait(ThreadSignal *tsig)
{
	xassert(!pthread_mutex_lock(&tsig->lock));
	while (!tsig->cvar)
		xassert(!pthread_cond_wait(&tsig->cond, &tsig->lock));
	tsig->cvar = 0;
	xassert(!pthread_mutex_unlock(&tsig->lock));
}

static int
seek_buffer(int64_t target_pts)
{
	int found = 0;

	uint16_t old_head = atomic_exchange_lax(&buffer_head, buffer_tail);
	/* Frame at head position could already been exchanged by sink
	 * thread to NULL or to an already played frame. We cannot rely
	 * on it so treat it as undefined and unconditionally skip it. */
	if (old_head != buffer_tail)
		++old_head;

	int64_t dropped_bytes = 0;

	for (; old_head != buffer_tail /* := buffer_head but owned */; ++old_head) {
		AVFrame *frame = buffer[old_head];

		if (frame->best_effort_timestamp <= target_pts &&
		    target_pts < frame->best_effort_timestamp + frame->pkt_duration)
		{
			frame->opaque = (void *)(size_t)1;
			atomic_store_lax(&cur_pts, frame->pts);
			atomic_store_explicit(&buffer_head, old_head, memory_order_release);
			found = 1;
			break;
		}

		dropped_bytes += frame->pkt_size;
		av_frame_unref(frame);
	}

	xassert(0 <= atomic_fetch_sub_lax(&buffer_bytes, dropped_bytes) - dropped_bytes);

	return found;
}

static void
sbprintf(char **pbuf, int *pn, char const *format, ...)
{
	va_list ap;
	va_start(ap, format);
	int rc = vsnprintf(*pbuf, *pn, format, ap);
	va_end(ap);

	assert(0 <= rc);
	if (*pn <= rc)
		rc = *pn;

	*pbuf += rc;
	*pn -= rc;
}

static void
print_stream(char **pbuf, int *pn, PlayerStream const *s, int output)
{
	static AVChannelLayout const CH_DEFAULT = AV_CHANNEL_LAYOUT_STEREO;

	if (!s->codec_ctx) {
		sbprintf(pbuf, pn, "(none)");
		return;
	}

	char const *format_name = output
		? s->format_ctx->oformat->name
		: s->format_ctx->iformat->name;
	char const *codec_name = s->codec_ctx->codec->name;
	sbprintf(pbuf, pn, "%s(%s)", format_name, codec_name);

	if (!output && AV_NOPTS_VALUE != s->audio->duration) {
		int64_t duration = av_rescale(
				s->audio->duration,
				s->audio->time_base.num,
				s->audio->time_base.den);
		sbprintf(pbuf, pn, ", %"PRId64":%02hu",
				duration / 60,
				(unsigned char)(duration % 60));
	}

	if (44100 != s->codec_ctx->sample_rate)
		sbprintf(pbuf, pn, ", %d Hz", s->codec_ctx->sample_rate);

	if (av_channel_layout_compare(&s->codec_ctx->ch_layout, &CH_DEFAULT)) {
		sbprintf(pbuf, pn, ", ");
		int n = av_channel_layout_describe(&s->codec_ctx->ch_layout, *pbuf, *pn);
		*pbuf += n;
		*pn -= n;
	}

	int64_t bit_rate = s->codec_ctx->bit_rate;
	if (!bit_rate)
		bit_rate = s->format_ctx->bit_rate;
	if (bit_rate)
		sbprintf(pbuf, pn, ", %"PRId64" kb/s", bit_rate / 1000);
}

static void
update_source_info(void)
{
	char *buf = source_info.buf[
		birdlock_wr_acquire(&source_info.lock)
	];

	int n = sizeof source_info.buf[0];

	print_stream(&buf, &n, &in.s, 0);
	if (in.cover_front) {
		AVCodecParameters *pars = in.cover_front->codecpar;
		if (pars)
			sbprintf(&buf, &n, "; cover_front(%s), %dx%d",
					avcodec_get_name(pars->codec_id),
					pars->width, pars->height);
		else
			sbprintf(&buf, &n, "; cover_front(none)");
	}

	birdlock_wr_release(&source_info.lock);
	tui_player_notify(PLAYER_EVENT_STREAM_CHANGED);
}

static void
update_sink_info(void)
{
	char *buf = sink_info.buf[
		birdlock_wr_acquire(&sink_info.lock)
	];

	int n = sizeof sink_info.buf[0];
	print_stream(&buf, &n, &out, 1);

	birdlock_wr_release(&sink_info.lock);
	tui_player_notify(PLAYER_EVENT_STREAM_CHANGED);
}

char const *
player_get_debug_info(void)
{
	static char buf[200];

	uint16_t len = atomic_load_lax(&buffer_tail) - atomic_load_lax(&buffer_head);
	sprintf(buf, "buf:%"PRId64"kB low:%"PRId64"kB usr:%"PRId64"kB max:%"PRId64"kB pkt:%"PRIu16,
			atomic_load_lax(&buffer_bytes) / 1024,
			atomic_load_lax(&buffer_low) / 1024,
			atomic_load_lax(&buffer_bytes_max) / 1024,
			len ? atomic_load_lax(&buffer_bytes) * (UINT16_MAX + 1) / len / 1024 : -1,
			len);

	return buf;
}

void
player_init(Error *error)
{
	(void)error;
	av_log_set_callback(player_libav_log_cb);
	av_log_set_level(AV_LOG_ERROR);
	avdevice_register_all();

	/* Set defaults. */
	update_source_info();
	update_sink_info();
}

static int
xdup2(int oldfd, int *newfd)
{
	if (0 <= *newfd)
		return dup2(oldfd, *newfd);
	else
		return (*newfd = dup(oldfd));
}

static void
output_close(void)
{
	if (out.header_written) {
		int rc = av_write_trailer(out.format_ctx);
		if (rc < 0)
			tui_msg_averror("Cannot close output", rc);
	}

	if (out.codec_ctx)
		avcodec_free_context(&out.codec_ctx);
	if (out.format_ctx) {
		avio_closep(&out.format_ctx->pb);
		avformat_free_context(out.format_ctx);
		out.format_ctx = NULL;
		out.header_written = 0;
	}
}

static void
graph_close(void)
{
	avfilter_graph_free(&graph);
}

static void
input_close(void)
{
	if (in.s.codec_ctx)
		avcodec_free_context(&in.s.codec_ctx);
	if (in.s.format_ctx) {
		avio_closep(&in.s.format_ctx->pb);
		avformat_close_input(&in.s.format_ctx);
	}
	if (0 <= in.fd)
		close(in.fd);
}

static void
input_destroy(void)
{
	input_close();

	for (int i = 0; i < 2; ++i) {
		PlayerSeekEvent *e = &in.seek_event[i];
		free(e->url);
		if (0 <= e->dirfd)
			close(e->dirfd);
	}

	for (int i = 0; i < 2; ++i) {
		PlayerMetadataEvent *e = &in.metadata_event[i];
		av_dict_free(&e->metadata);
	}
}

static void
input_write_cover(void)
{
	char tmp[PATH_MAX];
	if (safe_sprintf(tmp, "%s~", cover_path) < 0)
		return;

	int fd = open(tmp, O_CLOEXEC | O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IRGRP);
	if (fd < 0)
		return;

	uint8_t const *data;
	int data_size = 0;

	AVStream const *stream = in.cover_front;
	if (stream) {
		AVPacket const *pic = &stream->attached_pic;
		data = pic->data;
		data_size = pic->size;
	}

	if (data_size <= 0) {
		static uint8_t const DEFAULT_COVER[] =
		{
#include "cover.png.h"
		};

		data = DEFAULT_COVER;
		data_size = sizeof DEFAULT_COVER;
	}

	write(fd, data, data_size);
	close(fd);

	if (rename(tmp, cover_path))
		tui_msg_strerror("Cannot rename cover");
}

static void
update_metadata(void)
{
	PlayerMetadataEvent *e = &in.metadata_event[
		birdlock_wr_acquire(&in.metadata_lock)
	];

	e->f = in.f;

	AVCodecContext *codec_ctx = in.s.codec_ctx;
	e->sample_rate = codec_ctx ? codec_ctx->sample_rate : 0;
	e->codec_name = codec_ctx ? codec_ctx->codec->name : NULL;
	av_channel_layout_uninit(&e->ch_layout);
	memset(&e->ch_layout, 0, sizeof e->ch_layout);
	if (codec_ctx)
		(void)av_channel_layout_copy(&e->ch_layout, &codec_ctx->ch_layout);

	AVCodecParameters *pars =
		in.cover_front ? in.cover_front->codecpar : NULL;
	e->cover_codec_id = pars ? pars->codec_id : AV_CODEC_ID_NONE;
	e->cover_width = pars ? pars->width : 0;

	AVFormatContext *format_ctx = in.s.format_ctx;
	e->duration = format_ctx ? format_ctx->duration : 0;
	av_dict_free(&e->metadata);
	if (format_ctx) {
		e->metadata = format_ctx->metadata;
		format_ctx->metadata = NULL;
	} else {
		e->metadata = NULL;
	}

	struct stat st;
	if (0 <= in.fd && 0 <= fstat(in.fd, &st))
		e->mtime = st.st_mtime;
	else
		e->mtime = 0;

	birdlock_wr_release(&in.metadata_lock);
	tui_player_notify(PLAYER_EVENT_METADATA_CHANGED);
}

static void
input_open(PlayerSeekEvent *e)
{
	memset(&in.s, 0, sizeof in.s);

	char const *url;
	char url_buf[sizeof "pipe:" + 10];

	if (F_URL == e->type) {
		in.fd = -1;
		url = e->url;
	} else {
		in.fd = openat(e->dirfd, e->url, O_CLOEXEC | O_RDONLY);
		if (in.fd < 0) {
			tui_msgf("Cannot open '%s': %s", e->url, strerror(errno));
			return;
		}

		sprintf(url_buf, "pipe:%d", in.fd);
		url = url_buf;
	}

	int rc;

	rc = avformat_open_input(&in.s.format_ctx, url, NULL, NULL);
	if (rc < 0) {
		char error_buf[AV_ERROR_MAX_STRING_SIZE];
		av_make_error_string(error_buf, sizeof error_buf, rc);
		tui_msgf("Cannot open input '%s' ('%s'): %s", url, e->url, error_buf);
		return;
	}

	/* Get information on the input file (number of streams etc.). */
	(void)avformat_find_stream_info(in.s.format_ctx, NULL);

	in.cover_front = NULL;
	in.s.audio = NULL;

	unsigned ntracks = 0;

	for (unsigned i = 0; i < in.s.format_ctx->nb_streams; ++i) {
		AVStream *stream = in.s.format_ctx->streams[i];

		stream->discard = AVDISCARD_ALL;

		if (AVMEDIA_TYPE_AUDIO == stream->codecpar->codec_type) {
			if (e->track == ntracks)
				in.s.audio = stream;
			++ntracks;
			continue;
		}

		if ((AV_DISPOSITION_ATTACHED_PIC & stream->disposition) &&
		    AVMEDIA_TYPE_VIDEO == stream->codecpar->codec_type)
		{
			AVDictionaryEntry const *title;
			title = av_dict_get(stream->metadata, "comment", NULL, 0);
			if (!title)
				title = av_dict_get(stream->metadata, "MATROSKA/TITLE", NULL, 0);
			if (!title || strcasecmp(title->value, "Cover (front)"))
				continue;
			in.cover_front = stream;
		}
	}

	atomic_store_lax(&in.ntracks, ntracks);

	if (!in.s.audio) {
		tui_msgf("No audio streams found");
		return;
	}

#if 0
	AVStream *default_stream = in.s.format_ctx->streams[av_find_default_stream_index(in.s.format_ctx)];
	if (default_stream->opaque)
		in.s.audio = default_stream;
#endif

	in.s.audio->discard = 0;

	AVCodecParameters const *pars = in.s.audio->codecpar;
	/* Find a decoder for the audio stream. */
	AVCodec const *codec = avcodec_find_decoder(pars->codec_id);
	if (!codec) {
		tui_msgf("Cannot find %s decoder",
				avcodec_get_name(pars->codec_id));
		return;
	}

	/* Allocate a new decoding context. */
	if (!(in.s.codec_ctx = avcodec_alloc_context3(codec))) {
		tui_msgf("Cannot allocate codec");
		return;
	}

	/* Initialize the stream parameters with demuxer information. */
	rc = avcodec_parameters_to_context(in.s.codec_ctx, pars);
	if (rc < 0) {
		tui_msg_averror("Cannot initalize codec parameters", rc);
		return;
	}

	in.s.codec_ctx->time_base = in.s.audio->time_base;

	rc = avcodec_open2(in.s.codec_ctx, codec, NULL);
	if (rc < 0) {
		tui_msg_averror("Cannot open codec", rc);
		return;
	}
}

static int
graph_configure(AVBufferSrcParameters *pars, PlayerConfigureEvent *e)
{
	int rc;
	char const *error_msg = NULL;
	AVFilterInOut *src_end = NULL, *sink_end = NULL;

	graph_close();

	graph = avfilter_graph_alloc();
	if (!graph) {
	fail_enomem:
		rc = AVERROR(ENOMEM);
		error_msg = "Cannot allocate memory";
		goto out;
	}

	graph->nb_threads = 1;

	AVFilterContext *format_ctx;
	if (!(buffer_ctx = avfilter_graph_alloc_filter(graph,
			avfilter_get_by_name("abuffer"), "src")) ||
	    !(format_ctx = avfilter_graph_alloc_filter(graph,
			avfilter_get_by_name("aformat"), "aformat")) ||
	    !(buffersink_ctx = avfilter_graph_alloc_filter(graph,
			avfilter_get_by_name("abuffersink"), "sink")))
		goto fail_enomem;

	av_buffersrc_parameters_set(buffer_ctx, pars);

	char buf[128];
	(void)av_channel_layout_describe(&out.codec_ctx->ch_layout, buf, sizeof buf);
	(void)av_opt_set(format_ctx, "channel_layouts", buf, AV_OPT_SEARCH_CHILDREN);

	(void)av_opt_set(format_ctx, "sample_fmts",
			av_get_sample_fmt_name(out.codec_ctx->sample_fmt),
			AV_OPT_SEARCH_CHILDREN);

	snprintf(buf, sizeof buf, "%d", out.codec_ctx->sample_rate);
	(void)av_opt_set(format_ctx, "sample_rates", buf, AV_OPT_SEARCH_CHILDREN);

	if ((rc = avfilter_init_str(buffer_ctx, NULL)) < 0 ||
	    (rc = avfilter_init_str(format_ctx, NULL)) < 0 ||
	    (rc = avfilter_init_str(buffersink_ctx, NULL)) < 0)
	{
		error_msg = "Cannot initialize filters";
		goto out;
	}

	if (!(src_end = avfilter_inout_alloc()) ||
	    !(sink_end = avfilter_inout_alloc()))
		goto fail_enomem;

	/* Note: Allocation failure is gracefully handled by FFmpeg. */
	src_end->name = av_strdup("in");
	src_end->filter_ctx = buffer_ctx;
	/*
	 *   O
	 *   |
	 * User-supplied filtergraph.
	 *                         |
	 *                         O
	 */
	sink_end->name = av_strdup("out");
	sink_end->filter_ctx = format_ctx;

	rc = avfilter_link(sink_end->filter_ctx, 0, buffersink_ctx, 0);
	if (rc < 0) {
		error_msg = "Cannot create link";
		goto out;
	}

	rc = avfilter_graph_parse_ptr(graph, e->graph_descr, &sink_end, &src_end, NULL);
	if (rc < 0) {
		error_msg = "Cannot parse filtergraph";
		goto out;
	}

	rc = avfilter_graph_config(graph, NULL);
	if (rc < 0) {
		error_msg = "Cannot configure filtergraph";
		goto out;
	}

	graph_volume_volume = 100;

	if (AV_LOG_DEBUG <= av_log_get_level()) {
		char *str = avfilter_graph_dump(graph, NULL);
		av_log(graph, AV_LOG_DEBUG, "%s\n", str);
		av_free(str);
	}

out:
	if (rc < 0) {
		graph_close();

		char error_buf[AV_ERROR_MAX_STRING_SIZE];
		av_make_error_string(error_buf, sizeof error_buf, rc);
		tui_msgf("%s: %s", error_msg, error_buf);
	}

	avfilter_inout_free(&src_end);
	avfilter_inout_free(&sink_end);

	return rc;
}

static int
output_configure(AVFrame const *frame, PlayerConfigureEvent *e)
{
	if (e->native_codec && e->last_frame_format != frame->format) {
		e->last_frame_format = frame->format;
		e->codec = avcodec_find_encoder(av_get_pcm_codec(frame->format, -1));
	}

	/* Configuration not changed. */
	if (out.codec_ctx &&
	    out.codec_ctx->codec == e->codec &&
	    out.codec_ctx->sample_rate == frame->sample_rate &&
	    !av_channel_layout_compare(&out.codec_ctx->ch_layout, &frame->ch_layout))
		return 0;

	if (!e->codec) {
		tui_msgf("Unknown encoder");
		goto fail;
	}

	if (!e->format_name) {
		tui_msgf("Unknown output format");
		goto fail;
	}

	output_close();

	update_sink_info();

	int rc;

	rc = avformat_alloc_output_context2(&out.format_ctx, NULL,
			e->format_name, e->filename);
	if (rc < 0) {
		tui_msg_averror("Cannot allocate output format", rc);
		goto fail;
	}

	if (!(AVFMT_NOFILE & out.format_ctx->oformat->flags)) {
		rc = avio_open(&out.format_ctx->pb, e->filename, AVIO_FLAG_WRITE);
		if (rc < 0) {
			tui_msg_averror("Cannot open output file", rc);
			goto fail;
		}
	}

	if (!(out.audio = avformat_new_stream(out.format_ctx, NULL))) {
		tui_msg_averror("Cannot allocate output stream", rc);
		goto fail;
	}

	if (!(out.codec_ctx = avcodec_alloc_context3(e->codec))) {
		tui_msg_averror("Cannot allocate encoder", rc);
		goto fail;
	}

	if (out.format_ctx->flags & AVFMT_GLOBALHEADER)
		out.codec_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

	rc = av_channel_layout_copy(&out.codec_ctx->ch_layout, &frame->ch_layout);
	if (rc < 0) {
		tui_msg_averror("Could not copy channel layout", rc);
		goto fail;
	}
	out.codec_ctx->sample_rate = frame->sample_rate;
	out.codec_ctx->sample_fmt = e->codec->sample_fmts[0];
	out.codec_ctx->strict_std_compliance = FF_COMPLIANCE_EXPERIMENTAL;

	if (out.format_ctx->oformat->flags & AVFMT_GLOBALHEADER)
		out.codec_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

	if ((rc = avcodec_open2(out.codec_ctx, e->codec, NULL)) < 0 ||
	    (rc = avcodec_parameters_from_context(out.audio->codecpar, out.codec_ctx)) < 0)
	{
		tui_msg_averror("Cannot open encoder", rc);
		goto fail;
	}

	rc = avformat_write_header(out.format_ctx, NULL);
	if (rc < 0) {
		tui_msg_averror("Cannot write header", rc);
		goto fail;
	}

	out.header_written = 1;
	update_sink_info();

	return 1;

fail:
	output_close();
	return -1;
}

static void *
source_worker(void *arg)
{
	(void)arg;

	pthread_setname_np(pthread_self(), "muck/source");

	AVPacket *pkt = av_packet_alloc();
	if (!pkt) {
		tui_msg_oom();
		goto terminate;
	}

	int flush_output = 0;
	enum {
		S_RUNNING,
		S_STOPPED,
		S_STALLED,
	} state = S_STALLED;
	int64_t buffer_high = 0;

	for (;;) {
		int rc;

#if CONFIG_VALGRIND
		if (unlikely(atomic_load_lax(&terminate)))
			goto terminate;
#endif

		if (likely(!birdlock_rd_test(&in.seek_lock)))
			goto no_event;

		PlayerSeekEvent *e = &in.seek_event[
			birdlock_rd_acquire(&in.seek_lock)
		];

		int was_stalled = S_STALLED == state;

		if (e->url) {
			input_close();

			in.f = e->f;
			input_open(e);
			input_write_cover();
			update_source_info();
			update_metadata();

			/* Otherwise would be noise. */
			if (!in.s.codec_ctx)
				goto eof_reached;

			flush_output = !was_stalled;
			state = S_RUNNING;
			if (flush_output)
				seek_buffer(INT64_MIN);
			buffer_high = atomic_load_lax(&buffer_bytes_max);
		}

		if (likely(in.s.codec_ctx)) {
			int64_t target_pts = e->ts;
			switch (e->whence) {
			case SEEK_SET:
				/* Noop. */
				break;

			case SEEK_CUR:
				target_pts += atomic_load_lax(&cur_pts);
				break;

			case SEEK_END:
				target_pts += atomic_load_lax(&cur_duration);
				break;

			default:
				abort();
			}
			target_pts = MAXMIN(0, target_pts, cur_duration);

			e->whence = SEEK_CUR;
			e->ts = 0;

			/* A cheap way to save decoding a frame immediately but
			 * still showing something. */
			atomic_store_lax(&cur_pts, target_pts);
			tui_player_notify_progress();

			state = S_RUNNING;

			target_pts = av_rescale(target_pts,
					in.s.audio->time_base.den,
					in.s.audio->time_base.num);

			if (!was_stalled) {
				if (seek_buffer(target_pts))
					goto wakeup_sink;

				flush_output = 1;
			}

			/* Maybe interesting: out.codec_ctx->delay. */

			avcodec_flush_buffers(in.s.codec_ctx);
			rc = avformat_seek_file(in.s.format_ctx, in.s.audio->index,
					0, target_pts, target_pts, 0);
			if (rc < 0)
				tui_msg_averror("Cannot seek", rc);
		}
	no_event:

		int64_t tmp;
		if (/* Decoder stopped. */
		    unlikely(S_STALLED <= state) ||
		    /* Paused, do nothing. */
		    unlikely(atomic_load_lax(&paused)) ||
		    /* Buffer is loaded with enough data. */
		    (0 < (tmp = atomic_load_lax(&buffer_low)) ? tmp : buffer_bytes_max) <=
		     atomic_load_explicit(&buffer_bytes, memory_order_acquire) ||
		     /* Buffer is completely full. */
		    (unlikely(buffer_tail + 1 == atomic_load_lax(&buffer_head)) &&
		      /* buffer_bytes_max is too high so lower it. */
		     (buffer_high = atomic_load_lax(&buffer_bytes), 1)))
		{
		wait:;
			if (/* No more frames will arrive because decoder stopped. */
			    S_STOPPED == state &&
			    /* Buffer (almost) empty. */
			    (atomic_load_lax(&buffer_bytes) <= BUFFER_EOF_LOW ||
			     /* If last frame is larger than BUFFER_EOF_LOW,
			      * EOF signal would be sent only when all the
			      * buffer had been consumed. To avoid this, fire
			      * EOF event before reaching last frame. */
			     (uint16_t)(atomic_load_lax(&buffer_tail) - atomic_load_lax(&buffer_head)) <= 1))
			{
			eof_reached:;
				state = S_STALLED;
				tui_player_notify(PLAYER_EVENT_EOF_REACHED);
			}

			atomic_store_lax(&buffer_low, S_RUNNING == state
					? buffer_high / 2
					: S_STOPPED == state
					? BUFFER_EOF_LOW
					: 0);
			player_wait(&source_signal);
			continue;
		}

		AVFrame *frame = buffer[buffer_tail];

		if (!frame) {
			for (uint16_t to = atomic_load_lax(&buffer_head);
			     buffer_reap < to;
			     ++buffer_reap)
				if ((frame = buffer[buffer_reap])) {
					buffer[buffer_reap++] = NULL;
					break;
				}

			if (unlikely(!frame) &&
			    unlikely(!(frame = av_frame_alloc())))
			{
				tui_msg_oom();
				state = S_STOPPED;
				goto wait;
			}
			buffer[buffer_tail] = frame;
		}

		rc = av_read_frame(in.s.format_ctx, pkt);
		if (unlikely(state = rc < 0 ? S_STOPPED : S_RUNNING)) {
			if (AVERROR_EOF != rc)
				tui_msg_averror("Cannot read frame", rc);
			goto wait;
		}

		/* Packet from an uninteresting stream. */
		if (unlikely(in.s.audio->index != pkt->stream_index)) {
			av_packet_unref(pkt);
			continue;
		}

		if (unlikely((AVSTREAM_EVENT_FLAG_METADATA_UPDATED & in.s.format_ctx->event_flags))) {
			in.s.format_ctx->event_flags &= ~AVSTREAM_EVENT_FLAG_METADATA_UPDATED;
			/* Metadata may be moved out on open. Update only if
			 * there is something here. */
			if (in.s.format_ctx->metadata)
				update_metadata();
		}

		/* Send read packet for decoding. */
		rc = avcodec_send_packet(in.s.codec_ctx, pkt);
		av_packet_unref(pkt);
		if (unlikely(rc < 0))
			continue;

		/* Receive decoded frame. */
		rc = avcodec_receive_frame(in.s.codec_ctx, frame);
		if (unlikely(rc < 0))
			continue;

		atomic_fetch_add_lax(&buffer_bytes, frame->pkt_size);

		/* Unused by FFmpeg. */
		frame->pts = av_rescale(frame->pts,
				in.s.audio->time_base.num,
				in.s.audio->time_base.den);
		frame->opaque = (void *)(size_t)flush_output;
		flush_output = 0;

		atomic_store_lax(&cur_duration,
				AV_NOPTS_VALUE == in.s.format_ctx->duration
					? frame->pts
					: av_rescale(in.s.format_ctx->duration, 1, AV_TIME_BASE));

		int was_empty =
			atomic_load_lax(&buffer_head) ==
			atomic_fetch_add_explicit(&buffer_tail, 1, memory_order_release);
		if (unlikely(was_empty)) {
		wakeup_sink:
			player_signal(&sink_signal);
		}

		tui_player_notify_progress();
	}

terminate:
	av_packet_free(&pkt);

	return NULL;
}

static void
output_flush(void)
{
	if (out.codec_ctx)
		avcodec_flush_buffers(out.codec_ctx);
	if (out.format_ctx)
		av_write_frame(out.format_ctx, NULL);
}

static void
graph_update_volume(void)
{
	int desired_volume = atomic_load_lax(&volume);
	if (desired_volume < 0)
		desired_volume = 0;
	if (likely(graph_volume_volume == desired_volume))
		return;
	graph_volume_volume = desired_volume;

	double farg = pow(graph_volume_volume / 100., M_E);
	char arg[50];
	snprintf(arg, sizeof arg, "%f", farg);

	int rc = avfilter_graph_send_command(graph,
			"volume", "volume",
			arg, NULL, 0, 0);
	if (rc < 0) {
		if (!avfilter_graph_get_filter(graph, "volume"))
			tui_msgf("Cannot find 'volume' filter");
		tui_msgf("Cannot set volume");
	}
}

static void *
sink_worker(void *arg)
{
	(void)arg;

	pthread_setname_np(pthread_self(), "muck/sink");

	AVFrame *frame = NULL;
	int64_t out_dts = 0;

	AVPacket *pkt = av_packet_alloc();
	AVBufferSrcParameters *pars = av_buffersrc_parameters_alloc();

	if (!pkt || !pars) {
		tui_msg_oom();
		goto terminate;
	}

	pars->time_base = (AVRational){ 1, 1 };

	for (;;) {
#if CONFIG_VALGRIND
		if (unlikely(atomic_load_lax(&terminate)))
			goto terminate;
#endif

		if (unlikely(atomic_load_lax(&paused))) {
			output_flush();
			goto wait;
		}

		uint16_t head = atomic_load_lax(&buffer_head);
		if (unlikely(head == atomic_load_explicit(&buffer_tail, memory_order_acquire)))
			goto wait;

		if (0) {
		wait:
			player_wait(&sink_signal);
			continue;
		}

		frame = atomic_exchange_lax(&buffer[head], frame);
		/* If head stayed the same we can be sure that picked frame is valid. */
		if (unlikely(!atomic_compare_exchange_strong_explicit(
				&buffer_head, &head, head + 1,
				memory_order_relaxed, memory_order_relaxed)))
			continue;

		int rc;

		int64_t rem_bytes = atomic_fetch_sub_lax(&buffer_bytes, frame->pkt_size) - frame->pkt_size;
		assert(0 <= rem_bytes);
		if (rem_bytes <= atomic_load_lax(&buffer_low)) {
			atomic_store_lax(&buffer_low, INT64_MIN);
			player_signal(&source_signal);
		}

		PlayerConfigureEvent *e = &configure_event[
			birdlock_rd_acquire(&configure_lock)
		];

		int graph_changed = !graph;
#define xmacro(x) (graph_changed |= pars->x != frame->x, pars->x = frame->x)
		xmacro(format);
		xmacro(sample_rate);
		if (av_channel_layout_compare(&pars->ch_layout, &frame->ch_layout)) {
			graph_changed = 1;
			(void)av_channel_layout_copy(&pars->ch_layout, &frame->ch_layout);
		}
#undef xmacro

		rc = output_configure(frame, e);
		if (unlikely((!rc && graph_changed) || 0 < rc))
			rc = graph_configure(pars, e);
		if (unlikely(rc < 0)) {
			player_pause(1);
			continue;
		}

		graph_update_volume();

		if (unlikely(frame->opaque))
			output_flush();

		atomic_store_lax(&cur_pts, frame->pts);

		tui_player_notify_progress();

		frame->pts = out_dts;
		frame->pkt_dts = out_dts;
		frame->pkt_duration =
			frame->nb_samples
			* out.audio->time_base.den
			/ frame->sample_rate
			/ out.audio->time_base.num;

		rc = av_buffersrc_add_frame_flags(buffer_ctx, frame,
				AV_BUFFERSRC_FLAG_NO_CHECK_FORMAT);
		if (unlikely(rc < 0))
			tui_msg_averror("Cannot push frame into filtergraph", rc);

		rc = av_buffersink_get_frame_flags(buffersink_ctx, frame, 0);
		if (unlikely(rc < 0))
			tui_msg_averror("Cannot pull frame from filtergraph", rc);

		/* Send a frame to encode. */
		rc = avcodec_send_frame(out.codec_ctx, frame);
		if (unlikely(rc < 0))
			tui_msg_averror("Cannot encode frame", rc);

		av_frame_unref(frame);

		/* Receive an encoded packet. */
		while (0 <= (rc = avcodec_receive_packet(out.codec_ctx, pkt))) {
			out_dts += pkt->duration;

			rc = av_write_frame(out.format_ctx, pkt);
			if (unlikely(rc < 0))
				tui_msg_averror("Cannot write encoded frame", rc);
			av_packet_unref(pkt);
		}
		if (unlikely(AVERROR(EAGAIN) != rc))
			tui_msg_averror("Cannot receive encoded frame", rc);
	}

terminate:
	av_free(pars);
	av_frame_free(&frame);
	av_packet_free(&pkt);

	return NULL;
}

void
player_run(Error *error)
{
	sigset_t block_all, saved_mask;
	xassert(!sigfillset(&block_all));
	xassert(!pthread_sigmask(SIG_SETMASK, &block_all, &saved_mask));

	pthread_attr_t attr;
	struct sched_param sp;

	if (pthread_attr_init(&attr) ||
	    pthread_attr_setschedpolicy(&attr, SCHED_FIFO) ||
	    (sp.sched_priority = sched_get_priority_max(SCHED_FIFO)) < 0 ||
	    pthread_attr_setschedparam(&attr, &sp) ||
	    pthread_create(&source_thread, &attr, source_worker, NULL) ||
	    pthread_create(&sink_thread, &attr, sink_worker, NULL) ||
	    pthread_attr_destroy(&attr))
	{
		error_setf_strerror(error, "Failed to start threads");
		return;
	}

#if CONFIG_VALGRIND
	threads_inited = 1;
#endif

	xassert(!pthread_sigmask(SIG_SETMASK, &saved_mask, NULL));
}

File *
player_get_file(void)
{
	return in.seek_f;
}

void
player_seek_file(File const *f, int64_t ts, unsigned track)
{
	assert(f);

	PlayerSeekEvent *e = &in.seek_event[
		birdlock_wr_acquire(&in.seek_lock)
	];

	in.seek_f = (File *)f;
	e->f = (File *)f;
	Playlist *playlist = file_get_playlist(f);
	e->type = f->type;
	free(e->url);
	e->url = strdup(f->url);
	e->track = track;
	xdup2(playlist->dirfd, &e->dirfd);
	e->whence = SEEK_SET;
	e->ts = ts;

	birdlock_wr_release(&in.seek_lock);
	player_signal(&source_signal);
}

void
player_seek(int64_t ts, int whence)
{
	PlayerSeekEvent *e = &in.seek_event[
		birdlock_wr_acquire(&in.seek_lock)
	];

	int same_file = e->f == player_get_file();
	if (SEEK_CUR == whence && same_file) {
		e->ts += ts;
	} else {
		e->whence = whence;
		e->ts = ts;
	}
	free(e->url);
	e->url = NULL;
	e->f = player_get_file();

	birdlock_wr_release(&in.seek_lock);
	player_signal(&source_signal);
}

void
player_destroy(void)
{
#if CONFIG_VALGRIND
	if (threads_inited) {
		atomic_store_lax(&terminate, 1);
		player_signal(&source_signal);
		player_signal(&sink_signal);

		xassert(!pthread_join(source_thread, NULL));
		xassert(!pthread_join(sink_thread, NULL));
	}

	xassert(!pthread_mutex_destroy(&source_signal.lock));
	xassert(!pthread_cond_destroy(&source_signal.cond));
	xassert(!pthread_mutex_destroy(&sink_signal.lock));
	xassert(!pthread_cond_destroy(&sink_signal.cond));

	input_destroy();
	output_close();
	graph_close();

	uint16_t i = 0;
	do
		av_frame_free(&buffer[i]);
	while ((uint16_t)++i);
#endif
}

int64_t
player_get_clock(void)
{
	return atomic_load_lax(&cur_pts);
}

int64_t
player_get_duration(void)
{
	return atomic_load_lax(&cur_duration);
}

void
player_pause(int pause)
{
	atomic_store_lax(&paused, pause);
	if (!pause) {
		player_signal(&source_signal);
		player_signal(&sink_signal);
	}
	tui_player_notify(PLAYER_EVENT_PLAYBACK_CHANGED);
}

int
player_is_paused(void)
{
	return atomic_load_lax(&paused);
}

int
player_get_ntracks(void)
{
	return atomic_load_lax(&in.ntracks);
}

char const *
player_get_source_info(void)
{
	return source_info.buf[
		birdlock_rd_acquire(&source_info.lock)
	];
}

char const *
player_get_sink_info(void)
{
	return sink_info.buf[
		birdlock_rd_acquire(&sink_info.lock)
	];
}

int
player_get_volume(void)
{
	return atomic_load_lax(&volume);
}

void
player_set_volume(int n)
{
	atomic_store_lax(&volume, n);
}

void
player_set_buffer(int64_t bytes_max)
{
	atomic_store_lax(&buffer_bytes_max, bytes_max);
	player_signal(&source_signal);
}

void
player_configure(char const *format_name, char const *filename,
		char const *codec_name, char const *graph_descr)
{
	PlayerConfigureEvent *e = &configure_event[
		birdlock_wr_acquire(&configure_lock)
	];

#define STRINGS \
	xmacro(format_name) \
	xmacro(filename) \
	xmacro(graph_descr)

#define xmacro(name) (av_free(e->name), e->name = av_strdup(name));

	STRINGS

#undef xmacro

#undef STRINGS

	e->native_codec = !strcmp(codec_name, "pcm");
	e->codec = NULL;
	e->last_frame_format = AV_SAMPLE_FMT_NONE;

	if (!e->native_codec)
		e->codec = avcodec_find_encoder_by_name(codec_name);

	birdlock_wr_release(&configure_lock);
	player_signal(&sink_signal);
}

PlayerMetadataEvent *
player_get_metadata(void)
{
	PlayerMetadataEvent *e = &in.metadata_event[
		birdlock_rd_acquire(&in.metadata_lock)
	];
	return e->f == player_get_file() ? e : NULL;
}
