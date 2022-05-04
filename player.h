#ifndef MUCK_PLAYER_H
#define MUCK_PLAYER_H

#include <libavcodec/avcodec.h>
#include <libavutil/channel_layout.h>
#include <libavutil/dict.h>

#include "file.h"

typedef struct Error Error;

enum PlayerEvent {
	PLAYER_EVENT_PLAYBACK_CHANGED,
	PLAYER_EVENT_STREAM_CHANGED,
	PLAYER_EVENT_METADATA_CHANGED,
	PLAYER_EVENT_EOF_REACHED,
};

#define PLAYER_METADATA_EVENT_INITIALIZER { 0 }

typedef struct PlayerMetadataEvent {
	File *f;
	int icy;
	char const *codec_name;
	int bit_rate;
	int sample_rate;
	AVChannelLayout ch_layout;
	enum AVCodecID cover_codec_id;
	int cover_width;
	AVDictionary *metadata;
	int64_t duration;
	time_t mtime;
} PlayerMetadataEvent;

void player_init(Error *error);
void player_destroy(void);
void player_run(Error *error);

int player_get_volume(void);
void player_set_volume(int n);

void player_configure(char const *format_name, char const *filename,
		char const *codec_name, char const *graph_descr);
void player_set_buffer(int64_t bytes_max);

void player_seek_file(File const *f, int64_t ts, unsigned track);
File *player_get_file(void);
void player_seek(int64_t ts, int whence);
int player_get_ntracks(void);

int64_t player_get_clock(void);
int64_t player_get_duration(void);

void player_pause(int pause);
int player_is_paused(void);

char const *player_get_source_info(void);
char const *player_get_sink_info(void);
char const *player_get_debug_info(void);

PlayerMetadataEvent *player_get_metadata(void);

#endif
