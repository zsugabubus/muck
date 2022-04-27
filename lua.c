#include <assert.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <setjmp.h>
#include <stdio.h>

#include "env.h"
#include "error.h"
#include "expr.h"
#include "files.h"
#include "stdio_utils.h"
#include "tui.h"

#define LUA_ENTER (!ok || setjmp(panic_buf))

#define STATIC_ASSERT(cond) ((struct { int _; _Static_assert(cond); } *)0)

#if LUA_VERSION_NUM <= 501
# define luaL_setfuncs(L, l, nup) \
	(STATIC_ASSERT(0 == nup), luaL_register(L, NULL, l))
#endif

static lua_State *L;
static jmp_buf panic_buf;
static int ok = 1;

static int M_ref;

static int
l_msg_handler(lua_State *L)
{
	luaL_traceback(L, L, NULL, 0);
	fprintf(stderr, "lua: %s\n", lua_tostring(L, -1));
	lua_pop(L, 1);
	/* msg */
	return 1;
}

static void
l_log(char const *msg)
{
	tui_msgf("lua: %s", msg);
	fprintf(stderr, "lua: %s\n", msg);
}

static void
l_log_error(lua_State *L)
{
	char const *error_msg = lua_tostring(L, -1);
	l_log(error_msg);
	lua_pop(L, 1);
}

static void
l_error_ok_or_die(lua_State *L, Error const *error)
{
	if (!error_is_ok(error))
		luaL_error(L, "%s", error->msg);
}

static char *
l_strdup(lua_State *L, int index)
{
	char *str = strdup(luaL_checkstring(L, index));
	if (!str)
		luaL_error(L, "out of memory");
	return str;
}

static File *
l_checkfile(lua_State *L, int index)
{
	/* 0-based indexing is used. */
	int32_t pos = luaL_checkinteger(L, index);
	File *f = files_seek_wrap(pos, SEEK_SET, 0);
	if (!f)
		luaL_error(L, "no files");
	return f;
}

static int
l_checkwhence(lua_State *L, int index)
{
	char const *str = lua_tostring(L, index);
	if (!str ||
	    !strcmp(str, "set"))
		return SEEK_SET;
	else if (!strcmp(str, "cur"))
		return SEEK_CUR;
	else if (!strcmp(str, "end"))
		return SEEK_END;
	else
		luaL_argerror(L, index, "'set', 'cur', 'end' or none expected");
	abort();
}

static int
l_file2table(lua_State *L, File const *f)
{
	static char const TYPE_MAP[][10] = {
		[F_URL] = "url",
		[F_FILE] = "file",
		[F_PLAYLIST] = "playlist",
		[F_PLAYLIST_COMPRESSED] = "playlist",
		[F_PLAYLIST_DIRECTORY] = "dir",
	};

	if (!f)
		return 0;

	lua_createtable(L, 0, 2 + MX_NB);

	lua_pushstring(L, f->url);
	lua_setfield(L, -2, "url");

	lua_pushstring(L, TYPE_MAP[f->type]);
	lua_setfield(L, -2, "type");

	if (F_FILE == f->type)
		lua_pushstring(L, f->url);
	else
		lua_pushnil(L);
	lua_setfield(L, -2, "path");

	for (enum MetadataX m = 0; m < MX_NB; ++m) {
		char const *name = metadata_get_name(m);
		char buf[FILE_METADATAX_BUFSZ];
		char const *value = file_get_metadata(f, m, buf);
		if (value) {
			lua_pushstring(L, value);
			lua_setfield(L, -2, name);
		}
	}

	return 1;
}

static int
l_columns(lua_State *L)
{
	if (0 == lua_gettop(L)) {
		lua_pushstring(L, tui_get_columns());
		return 1;
	} else {
		tui_set_columns(l_strdup(L, 1));
		return 0;
	}
}

static int
l_error(lua_State *L)
{
	tui_msgf("%s", luaL_checkstring(L, 1));
	return 0;
}

static int
l_feedkeys(lua_State *L)
{
	tui_feed_keys(luaL_checkstring(L, 1));
	return 0;
}

static int
l_file(lua_State *L)
{
	int whence = l_checkwhence(L, 2);

	File const *f;
	if (LUA_TSTRING == lua_type(L, 1)) {
		char const *str = lua_tostring(L, 1);
		if (strcmp(str, "random"))
			luaL_argerror(L, 1, "number or 'random' expected");
		f = files_seek_rnd(whence);
	} else {
		int32_t pos = lua_tointeger(L, 1);
		f = files_seek(pos, whence);
	}

	return l_file2table(L, f);
}

static int
l_filter(lua_State *L)
{
	ExprParserContext parser;
	error_reset(&parser.error);
	files_set_filter(&parser, l_strdup(L, 1));
	l_error_ok_or_die(L, &parser.error);
	return 0;
}

static int
l_move(lua_State *L)
{
	File const *f = l_checkfile(L, 1);
	int32_t pos = luaL_checkinteger(L, 2);
	int whence = l_checkwhence(L, 3);
	(void)files_move(f, pos, whence);
	tui_notify(TUI_EVENT_FILES_CHANGED);
	return 0;
}

static int
l_output(lua_State *L)
{
#define xmacro(name) \
	char const *name = ( \
		lua_getfield(L, 1, #name), \
		luaL_checkstring(L, -1) \
	)
	xmacro(format);
	xmacro(filename);
	xmacro(codec);
	xmacro(graph);
#undef xmacro
	player_configure(format, filename, codec, graph);
	return 0;
}

static int
l_pause(lua_State *L)
{
	if (0 == lua_gettop(L)) {
		lua_pushboolean(L, player_is_paused());
		return 1;
	} else {
		player_pause(lua_toboolean(L, 1));
		return 0;
	}
}

static int
l_progress(lua_State *L)
{
	lua_pushinteger(L, player_get_clock());
	lua_pushinteger(L, player_get_duration());
	return 2;
}

static int
l_seek(lua_State *L)
{
	int64_t ts = luaL_checkinteger(L, 1);
	int whence = l_checkwhence(L, 2);
	player_seek(ts, whence);
	return 0;
}

static int
l_seek_file(lua_State *L)
{
	File *f = l_checkfile(L, 1);
	int64_t ts = lua_tointeger(L, 2);
	unsigned track = lua_tointeger(L, 3);
	player_seek_file(f, ts, track);
	return 0;
}

static int
l_select(lua_State *L)
{
	files_select(l_checkfile(L, 1));
	return 0;
}

static int
l_sort(lua_State *L)
{
	if (0 == lua_gettop(L)) {
		lua_pushstring(L, files_get_order());
		return 1;
	} else {
		files_set_order(l_strdup(L, 1));
		return 0;
	}
}

static int
l_track(lua_State *L)
{
	lua_pushnil(L);
	lua_pushinteger(L, player_get_ntracks());
	return 2;
}

static int
l_volume(lua_State *L)
{
	if (0 == lua_gettop(L)) {
		lua_pushinteger(L, player_get_volume());
		return 1;
	} else {
		player_set_volume(luaL_checkinteger(L, 1));
		tui_notify(TUI_EVENT_STATUS_LINE_CHANGED);
		return 0;
	}
}

static int
luaopen_muck(lua_State *L)
{
	static char const SOURCE[] =
	{
#include "muck.lua.h"
		'\0',
	};

#define xmacro(name) { #name, l_##name }
	static luaL_Reg const REGISTRY[] = {

		xmacro(columns),
		xmacro(error),
		xmacro(feedkeys),
		xmacro(file),
		xmacro(filter),
		xmacro(move),
		xmacro(output),
		xmacro(pause),
		xmacro(progress),
		xmacro(seek),
		xmacro(seek_file),
		xmacro(select),
		xmacro(sort),
		xmacro(track),
		xmacro(volume),

		{ NULL },
	};
#undef xmacro

	luaL_dostring(L, SOURCE);

	luaL_setfuncs(L, REGISTRY, 0);

	lua_pushvalue(L, -1);
	M_ref = luaL_ref(L, LUA_REGISTRYINDEX);

	return 1;
}

static int
l_panic(lua_State *L)
{
	(void)L;
	longjmp(panic_buf, 1);
	l_log("Lua panic!");
	ok = 0;
	return 0;
}

void
l_open(void)
{
	char rc_path[PATH_MAX];
	if (safe_sprintf(rc_path, "%s/rc.lua", config_home)) {
		tui_msgf("$MUCK_HOME/rc.lua is too long");
		return;
	}

	if (!(L = luaL_newstate())) {
		l_log("Failed to allocate context");
		return;
	}

	lua_atpanic(L, l_panic);

	if (LUA_ENTER)
		return;

	luaL_openlibs(L);

	lua_getglobal(L, "package");
	lua_getfield(L, -1, "loaded");
	luaopen_muck(L);
	lua_setfield(L, -2, "muck");
	lua_pop(L, 2);

	lua_pushcfunction(L, l_msg_handler);
	if (luaL_loadfile(L, rc_path) ||
	    lua_pcall(L, 0, 0, -2))
		l_log_error(L);
}

void
l_destroy(void)
{
	if (L)
		lua_close(L);
}

static void
l_get_hook(char const *name)
{
	lua_pushcfunction(L, l_msg_handler);
	lua_rawgeti(L, LUA_REGISTRYINDEX, M_ref);
	lua_getfield(L, -1, name);
	lua_replace(L, -2);
}

static int
l_call_hook(int nargs)
{
	if (lua_pcall(L, nargs, 1, -(nargs + 1 /* fn */ + 1 /* msgh */))) {
		l_log_error(L);
		return 0;
	}

	int prevent_default = lua_toboolean(L, -1);
	lua_pop(L, 1);
	return prevent_default;
}

int
l_hook_on_eof(void)
{
	if (LUA_ENTER)
		return 0;

	l_get_hook("on_eof");
	return l_call_hook(0);
}

int
l_hook_on_key(char const *key)
{
	if (LUA_ENTER)
		return 0;

	l_get_hook("on_key");
	lua_pushstring(L, key);
	return l_call_hook(1);
}
