#ifndef MUCK_TUI_H
#define MUCK_TUI_H

#include "player.h"

typedef struct Error Error;

enum TUIEvent {
	TUI_EVENT_FILES_CHANGED = 1 << 0,
	TUI_EVENT_STATUS_LINE_CHANGED = 1 << 1,
	TUI_EVENT_METADATA_CHANGED = 1 << 2,
	TUI_EVENT_EOF_REACHED = 1 << 3,
};

void tui_init(void);
void tui_destroy(void);
void tui_run(void);

void tui_feed_key(int c);
void tui_feed_keys(char const *s);

void tui_set_columns(char const *spec);

void tui_notify(enum TUIEvent event);
void tui_player_notify(enum PlayerEvent event);
void tui_player_notify_progress(void);

void tui_msgf(char const *format, ...);
void tui_msg_error(Error *error);
void tui_msg_strerror(char const *msg);
void tui_msg_oom(void);
void tui_msg_strerror_oom(void);

int tui_shellout(void);

void tui_handle_files_change(void);

#endif
