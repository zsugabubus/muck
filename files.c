#include "assert_utils.h"
#include "atomic_utils.h"
#include "config.h"
#include "math_utils.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#if WITH_ICU
# include <unicode/ucol.h>
# include <unicode/parseerr.h>
#endif

#include "error.h"
#include "expr.h"
#include "files.h"
#include "files_par.h"
#include "player.h"
#include "playlist.h"
#include "rnd.h"
#include "tui.h"

typedef struct {
	Expr *query;
	uint8_t filter_index;
} MatchFileContext;

int32_t nfiles[FILTER_COUNT];
File **files;
int live = 1;

static int32_t sel = -1;

static char const DEFAULT_SORT_SPEC[] = "";
static char *sort_spec[2] = {
	(char *)DEFAULT_SORT_SPEC,
	(char *)DEFAULT_SORT_SPEC,
};
static int order_changed[2];
#if WITH_ICU
static UCollator *sort_ucol;
#endif

static RndState rnd;

static pcre2_match_data *re_match_data;

static Expr *filter_exprs[FILTER_COUNT];
static int filter_changed[FILTER_COUNT];

uint8_t cur_filter[2] = {
	FILTER_FILES,
	FILTER_FILES,
};
char *search_history[10];

static void
push_history(char **history, size_t nhistory, char *s)
{
	char *carry = history[0];
	history[0] = s;
	for (size_t i = 1; i < nhistory && carry; ++i) {
		if (!strcmp(carry, s)) {
			free(carry);
			return;
		}

		SWAP(char *, history[i], carry);
	}
	free(carry);
}

static Expr *
parse_filter_spec(ExprParserContext *parser, char const *s)
{
	Expr *query = NULL;

	error_reset(&parser->error);
	parser->cur = player_get_file();
	parser->ptr = parser->src = s;
	parser->match_data = re_match_data;

	query = expr_parse(parser);
	if (!error_is_ok(&parser->error))
		goto fail;

	if (!expr_depends_key(query, MX_playlist)) {
		parser->src = parser->ptr = "p~^[^-]";

		Expr *expr = expr_alloc(EXPR_AND);
		if (!expr) {
			error_from_strerror(&parser->error, ENOMEM);
			goto fail;
		}
		if (!(expr->bi.rhs = expr_parse(parser))) {
			expr_free(expr);
			goto fail;
		}
		expr->bi.rhs->parent = expr;
		(expr->bi.lhs = query)->parent = expr;
		query = expr;
	}

	expr_optimize(&query);

	return query;

fail:
	expr_free(query);
	return NULL;
}

static void
load_saved_order(void)
{
	/* Indices are good. */
	if (order_changed[live])
		return;

	/* Initialize unused indices. */
	for (int32_t i = nfiles[cur_filter[!live]];
	     i < nfiles[FILTER_ALL]; ++i)
		files[i]->index[!live] = i;

	/* Restore order using saved indices. */
	int32_t n = nfiles[cur_filter[live]];
	for (int32_t i = 0; i < n; ++i)
		for (int32_t to; i != (to = files[i]->index[live]);)
			SWAP(File *, files[i], files[to]);
}

static int
file_cmp(void const *px, void const *py)
{
	File const *x = *(File **)px;
	File const *y = *(File **)py;

	uint8_t filter_mask = UINT8_C(1) << cur_filter[live];
	if (!(x->filter_mask & y->filter_mask & filter_mask))
		return !!(x->filter_mask & filter_mask) - !!(y->filter_mask & filter_mask);

	for (char const *s = sort_spec[live]; *s; ++s) {
		int cmp = 0;

		enum MetadataX m;
		if (!metadata_parse(&m, *s)) {
			tui_msgf("invalid sort specifier '%c'", *s);
			break;
		}

		int numeric;
		s += (numeric = '=' == s[1]);
		int neg;
		s += (neg = '-' == s[1]);

		char bufx[FILE_METADATAX_BUFSZ];
		char bufy[FILE_METADATAX_BUFSZ];
		char const *vx = file_get_metadata(x, m, bufx);
		char const *vy = file_get_metadata(y, m, bufy);

		if (!vx || !vy) {
			cmp = !vy - !vx;
			goto decide;
		}

		if (numeric) {
			char const *px = vx;
			char const *py = vy;
			int any = 0;
			for (;;) {
				int32_t nx, ny;
				px = expr_strtoi(px, &nx);
				py = expr_strtoi(py, &ny);
				if (px && py) {
					any = 1;
					if (nx == ny)
						continue;
					cmp += DIFFSIGN(nx, ny);
				} else {
					cmp += !!px - !!py;
				}
				break;
			}

			if (any)
				goto decide;
		}

		for (char const *px = vx;;) {
			char *px_end = strchrnul(px, ';');
			size_t nx = px_end - px;

			for (char const *py = vy;;) {
				char *py_end = strchrnul(py, ';');
				size_t ny = py_end - py;

#if WITH_ICU
				/* TODO: Maybe compare without space and
				 * space-like characters. */
				UErrorCode error_code = U_ZERO_ERROR;
				UCollationResult rc = ucol_strcollUTF8(sort_ucol,
						px, nx, py, ny, &error_code);
				assert(U_SUCCESS(error_code));
				int c =
					UCOL_LESS == rc ? -1 :
					UCOL_GREATER == rc ? 1 :
					0;
#else
				size_t n = MIN(nx, ny);
				int c = memcmp(px, py, n);
#endif
				if (!c)
					c = FFDIFFSIGN(nx, ny);
				else
					c = FFDIFFSIGN(c, 0);
				cmp += c;

				if (!*py_end)
					break;
				py = py_end + 1;
			}

			if (!*px_end)
				break;
			px = px_end + 1;
		}

	decide:
		if (cmp)
			return neg ? -cmp : cmp;
	}

	return 0;
}

static int
file_is_ordered(File const *f, int l)
{
	/* Indices are good. */
	if (order_changed[l])
		return 0;

	int32_t n = cur_filter[l];
	return
		(!f->index[l] || file_cmp(&files[f->index[l] - 1], &f) <= 0) &&
		(nfiles[n] == f->index[l] + 1 || file_cmp(&f, &files[f->index[l] + 1]) <= 0);
}

static void
files_dirty_filter(uint8_t filter_index)
{
	for (int l = 0; l < 2; ++l)
		order_changed[l] |= filter_index == cur_filter[l];
}

void
files_dirty_single(File *f)
{
	/* Update f->filter_mask. */
	for (uint8_t filter_index = FILTER_CUSTOM_0;
	     filter_index < FILTER_COUNT;
	     ++filter_index)
	{
		Expr *query = filter_exprs[filter_index];
		if (!query)
			continue;

		uint8_t filter_mask = UINT8_C(1) << filter_index;
		int match = expr_eval(query, &(ExprEvalContext const){
			.f = f,
			.match_data = re_match_data,
		});
		if (match == !!(filter_mask & f->filter_mask))
			continue;

		f->filter_mask ^= filter_mask;
		nfiles[filter_index] += match ? 1 : -1;

		files_dirty_filter(filter_index);
	}

	/* Check whether file order changed. */
	for (int l = 0; l < 2; ++l)
		if (!file_is_ordered(f, l))
			order_changed[l] = 1;
}

void
files_dirty_batch(void)
{
	order_changed[0] = 1;
	order_changed[1] = 1;
	for (uint8_t filter_index = FILTER_CUSTOM_0;
	     filter_index < FILTER_COUNT;
	     ++filter_index)
		filter_changed[filter_index] = 1;
}

static void
file_plumb(File const *f, uint8_t filter_index, FILE *stream)
{
	if (!(f->filter_mask & (UINT8_C(1) << filter_index)))
		return;

	Playlist *playlist = file_get_playlist(f);
	if (F_FILE == f->type &&
	    '/' != *f->url)
	{
		char const *dirname = playlist->dirname;
		if (!dirname) {
			fputs("(error)", stream);
		} else if ('.' == dirname[0] &&
		           (!dirname[1] || '/' == dirname[1]))
		{
			/* Nothing. */
		} else {
			fputs(dirname, stream);
			fputc('/', stream);
		}
	}
	fputs(f->url, stream);

	for (enum Metadata i = 0; i < M_NB; ++i) {
		fputc('\t', stream);
		if (f->metadata[i])
			fputs(f->url + f->metadata[i], stream);
	}

	fputc('\n', stream);
}

static int
match_file_worker(FileWorker *worker, void const *arg)
{
	pcre2_match_data *match_data = pcre2_match_data_create(0, NULL);
	if (!match_data)
		return -ENOMEM;

	MatchFileContext const *ctx = arg;
	uint8_t filter_mask = UINT8_C(1) << ctx->filter_index;

	int32_t n = 0;
	for (File *f; (f = files_par_next(worker));) {
		/* Hide playlists. */
		if (F_FILE < f->type)
			continue;

		if (expr_eval(ctx->query, &(ExprEvalContext const){
			.f = f,
			.match_data = match_data,
		})) {
			f->filter_mask |= filter_mask;
			++n;
		} else {
			f->filter_mask &= ~filter_mask;
		}
	}

	pcre2_match_data_free(match_data);

	atomic_fetch_add_lax(&nfiles[ctx->filter_index], n);
	return 0;
}

static void
files_do_filtersort(void)
{
	if (!order_changed[live])
		return;

	uint8_t filter_index = cur_filter[live];
	if (filter_changed[filter_index]) {
		filter_changed[filter_index] = 0;
		/* TODO: Cache filters. */
		nfiles[filter_index] = 0;
		(void)files_par_iter(match_file_worker, &(MatchFileContext){
			.query = filter_exprs[filter_index],
			.filter_index = filter_index,
		});
	}
	order_changed[live] = 0;

	uint8_t filter_mask = UINT8_C(1) << filter_index;
	int32_t n = nfiles[filter_index];
	File *cur = 0 <= sel ? files[sel] : NULL;

	int32_t k = 0;
	for (int32_t i = 0; i < nfiles[FILTER_ALL] && k < n; ++i)
		if (filter_mask & files[i]->filter_mask) {
			if (k != i)
				SWAP(File *, files[k], files[i]);
			++k;
		}

	assert(n == k);

	qsort(files, n, sizeof *files, file_cmp);

	for (int32_t i = 0; i < n; ++i)
		files[i]->index[live] = i;

	if (cur && (filter_mask & cur->filter_mask))
		sel = cur->index[live];
	else
		sel = MIN(MAX(0, sel), n - 1);

	tui_notify(TUI_EVENT_FILES_CHANGED);
}

char const *
files_get_order(void)
{
	return sort_spec[live];
}

void
files_set_order(char *spec)
{
	if (!strcmp(spec, sort_spec[live])) {
		free(spec);
		return;
	}

	if (DEFAULT_SORT_SPEC != sort_spec[live])
		free(sort_spec[live]);
	sort_spec[live] = spec;

	order_changed[live] = 1;
	tui_notify(TUI_EVENT_FILES_CHANGED);
}

void
files_set_filter(ExprParserContext *parser, char *s)
{
	push_history(search_history, FF_ARRAY_ELEMS(search_history), s);

	Expr *query = parse_filter_spec(parser, s);
	if (!query)
		return;

	cur_filter[live] = FILTER_CUSTOM_0 + live;
	uint8_t filter_index = cur_filter[live];

	expr_free(filter_exprs[filter_index]);
	filter_exprs[filter_index] = query;

	filter_changed[filter_index] = 1;

	files_dirty_filter(filter_index);
	tui_handle_files_change();
	tui_notify(TUI_EVENT_FILES_CHANGED);
}

File *
files_seek_rnd(int whence)
{
	files_do_filtersort();

	uint8_t filter_index = cur_filter[live];
	int32_t n = nfiles[filter_index];
	if (!n)
		return NULL;

	int32_t pos = rnd_nextn(&rnd, n - (SEEK_CUR == whence));
	return files_seek(pos, whence);
}

File *
files_seek(int32_t pos, int whence)
{
	files_do_filtersort();

	uint8_t filter_index = cur_filter[live];
	int32_t n = nfiles[filter_index];
	if (!n)
		return NULL;

	if (SEEK_SET == whence) {
		/* Noop. */
	} else if (SEEK_END == whence) {
		pos = n - 1 - pos;
	} else if (SEEK_CUR == whence) {
		if (live) {
			File const *playing = player_get_file();
			pos +=
				playing &&
				((UINT8_C(1) << filter_index) & playing->filter_mask)
					? playing->index[live]
					: 0;
		} else {
			pos += sel;
		}
	} else {
		abort();
	}

	pos %= n;
	if (pos < 0)
		pos += n;

	return files[pos];
}

void
files_set_live(int new_live)
{
	if (new_live == live)
		return;
	live = new_live;

	load_saved_order();
}

void
files_select(File const *f)
{
	sel = f->index[live];
}

void
files_plumb(FILE *stream)
{
	(void)files_seek(0, SEEK_CUR);

	fputs("path", stream);
	for (enum Metadata i = 0; i < M_NB; ++i) {
		fputc('\t', stream);
		fputs(metadata_get_name((enum MetadataX)i), stream);
	}
	fputc('\n', stream);

	int32_t filter_index = cur_filter[live];
	int32_t n = nfiles[filter_index];
	for (int32_t i = 0; i < n; ++i)
		file_plumb(files[i], filter_index, stream);
}

void
files_destroy(void)
{
	for (int32_t i = 0; i < nfiles[FILTER_ALL]; ++i)
		file_free(files[i]);

	playlists_destroy();

	pcre2_match_data_free(re_match_data);

#if WITH_ICU
	if (sort_ucol)
		ucol_close(sort_ucol);
#endif

	for (size_t i = 0; i < FF_ARRAY_ELEMS(search_history); ++i)
		free(search_history[i]);

	for (int i = 0; i < 2; ++i)
		if (DEFAULT_SORT_SPEC != sort_spec[i])
			free(sort_spec[i]);

	for (size_t i = 0; i < FF_ARRAY_ELEMS(filter_exprs); ++i)
		expr_free(filter_exprs[i]);
}

void
files_init(Error *error)
{
	if (rnd_init(&rnd)) {
		error_setf_strerror(error, "Could not initalize PRNG");
		return;
	}

	re_match_data = pcre2_match_data_create(0, NULL);
	if (!re_match_data) {
		error_from_strerror(error, ENOMEM);
		return;
	}

#if WITH_ICU
	UParseError parse_error;
	UErrorCode error_code = U_ZERO_ERROR;
	sort_ucol = ucol_openRules((UChar const[1]){ 0 }, 0,
			/* Normalize. */
			UCOL_ON,
			/* Compare base letters case-less. */
			UCOL_PRIMARY,
			&parse_error, &error_code);
	if (U_FAILURE(error_code)) {
		error_from_icu_error(error, error_code);
		return;
	}
#endif

	files_par_init();
}
