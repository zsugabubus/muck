#include "math_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../playlist.h"
#include "../fdata.h"
#include "../expr.h"

#include "error.h"

static ExprParserContext parser;

#define bprint(...) (*buf += sprintf(*buf, __VA_ARGS__))

static void
expr_dump(Expr *expr, char **buf)
{
	bprint("(");
	switch (expr->type) {
	case EXPR_TRUE:
		bprint("TRUE");
		break;

	case EXPR_NEG:
		bprint("! ");
		/* FALLTHROUGH */
	case EXPR_GROUP:
		expr_dump(expr->un.expr, buf);
		break;

	case EXPR_AND:
	case EXPR_OR:
		expr_dump(expr->bi.lhs, buf);
		bprint(EXPR_AND == expr->type ? " & " : " | ");
		expr_dump(expr->bi.rhs, buf);
		break;

	case EXPR_KV:
		if (expr->kv.keys == METADATASET_IN_URL) {
			bprint("{url}");
		} else {
			for each_metadata(m, expr->kv.keys)
				bprint("%c", metadata_get_id(m));
		}
		if (KOP_LT & expr->kv.op) bprint("<");
		if (KOP_EQ & expr->kv.op) bprint("=");
		if (KOP_GT & expr->kv.op) bprint(">");
		if (KOP_ISSET & expr->kv.op) bprint("?");
		if (KOP_RE & expr->kv.op) {
			bprint("~");
		} else {
			for (int i = 0; i < expr->kv.nnums; ++i)
				bprint("%d,", (int)expr->kv.nums[i]);
		}
		break;

	default:
		abort();
	}
	bprint(")");
}

static void
assert_expr(Expr *e, char const *wanted)
{
	assert(e);

	char got[200];
	expr_dump(e, &(char *){ got });
	assert(!strcmp(got, wanted));
	expr_free(e);
}

static void
assert_expr_optimize(Expr *e, char const *wanted)
{
	assert(e);
	expr_optimize(&e);
	assert_expr(e, wanted);
}

static void
assert_expr_parse_ok(char const *s, char const *wanted)
{
	error_reset(&parser.error);
	parser.ptr = parser.src = s;

	Expr *e = expr_parse(&parser);
	assert_expr(e, wanted);
}

static void
assert_expr_parse_fail(char const *s, int error_col, char const *error_msg)
{
	error_reset(&parser.error);
	parser.ptr = parser.src = s;

	Expr *e = expr_parse(&parser);
	assert(!e);
	assert((int)(parser.ptr - s) == error_col);
	assert(strstr(parser.error.msg, error_msg));
}

static void
assert_expr_parse_optimize(char const *s, char const *wanted)
{
	error_reset(&parser.error);
	parser.ptr = parser.src = s;

	Expr *e = expr_parse(&parser);
	assert_expr_optimize(e, wanted);
}

static void
test_expr(void)
{
	Error error;
	error_reset(&error);
	expr_global_init(&error);
	assert(!error.msg);
	parser.match_data = pcre2_match_data_create(0, NULL);

	assert_expr_parse_ok("", "((TRUE))");
	assert_expr_parse_fail("t~", 2, "file");
	assert_expr_parse_fail(")", 0, "xpected");
	assert_expr_parse_fail("|", 0, "xpected");
	assert_expr_parse_fail("(|", 1, "xpected");
	assert_expr_parse_fail("(~x |&", 5, "xpected");
	assert_expr_parse_fail("(~x &|", 5, "xpected");
	assert_expr_parse_fail("(~x &)", 5, "xpected");
	assert_expr_parse_fail("(~x &!", 6, "end");
	assert_expr_parse_fail("!!)", 2, "xpected");
	assert_expr_parse_fail("!", 1, "end");
	assert_expr_parse_fail("~e)", 2, ")");
	assert_expr_parse_fail("!!!!X~", 4, "nknown");
	{
		enum { N = 9999 };
		char buf[N + 1];
		memset(buf, '(', N);
		buf[N] = '\0';
		assert_expr_parse_fail(buf, N, "end");
	}
	assert_expr_parse_ok("(AaaAAa~b", "(((aA~)))");
	assert_expr_parse_ok("~x | !!(!~a ~b | ~c !!~d)", "((({url}~) | (! (! ((((! ({url}~)) & ({url}~)) | (({url}~) & (! (! ({url}~))))))))))");

	assert_expr_parse_ok("'helo'", "(({url}~))");
	assert_expr_parse_ok("t\"bla (|~&~|) bla\"", "((t~))");
	assert_expr_parse_ok("y<=-2000-x-2", "((y<=2000,2,))");
	assert_expr_parse_ok("(t~hell)~o", "((((t~)) & ({url}~)))");
	assert_expr_parse_ok("!!t~hell~o|a~b", "(((! (! (t~))) | (a~)))");
	assert_expr_parse_ok("!!t~hell ~o", "(((! (! (t~))) & ({url}~)))");

	assert_expr_parse_ok("!!t~hell ~o", "(((! (! (t~))) & ({url}~)))");

	File f = { 0 };
	parser.cur = &f;
	assert_expr_parse_ok("t~", "((t~))");

	assert_expr_parse_optimize("", "(TRUE)");
	assert_expr_parse_optimize("!t''", "(! (t~))");
	assert_expr_parse_optimize("!!t''", "(t~)");
	assert_expr_parse_optimize("!!!!t''", "(t~)");
	assert_expr_parse_optimize("!!!!!t''", "(! (t~))");
	assert_expr_parse_optimize("(((t'')))", "(t~)");
	assert_expr_parse_optimize("(!(!(!t'')))", "(! (t~))");
	assert_expr_parse_optimize("(!!(!!(!(!!!t''))))", "(t~)");
	assert_expr_parse_optimize("(!(!(!(a'')))) | !!!!!!(t'')", "((t~) | (! (a~)))");
	assert_expr_parse_optimize("~x at~y t~z | (((!!!!!!=4)))", "(({url}=4,) | ((t~) & ((at~) & ({url}~))))");

	Expr *e, *e2;
	e = expr_alloc(EXPR_AND);
	expr_free(e);

	e = expr_alloc(EXPR_AND);
	(e->bi.lhs = expr_alloc(EXPR_AND))->parent = e;
	expr_free(e);

	e = expr_alloc(EXPR_AND);
	(e->bi.rhs = expr_alloc(EXPR_AND))->parent = e;
	expr_free(e);

	e = expr_alloc(EXPR_AND);
	(e->bi.lhs = expr_alloc(EXPR_TRUE))->parent = e;
	(e->bi.rhs = expr_alloc(EXPR_TRUE))->parent = e;
	assert_expr_optimize(e, "(TRUE)");

	e2 = expr_alloc(EXPR_NEG);
	(e2->un.expr = expr_alloc(EXPR_TRUE))->parent = e2;
	e = expr_alloc(EXPR_OR);
	(e->bi.lhs = e2)->parent = e;
	(e->bi.rhs = expr_alloc(EXPR_TRUE))->parent = e;
	assert_expr_optimize(e, "(TRUE)");

	/* Short circuiting. */
	e = expr_alloc(EXPR_OR);
	(e->bi.lhs = expr_alloc(EXPR_TRUE))->parent = e;
	assert(expr_eval(e, NULL));
	expr_free(e);

	e2 = expr_alloc(EXPR_NEG);
	(e2->un.expr = expr_alloc(EXPR_TRUE))->parent = e2;
	e = expr_alloc(EXPR_AND);
	(e->bi.lhs = e2)->parent = e;
	assert(!expr_eval(e, NULL));
	expr_free(e);
}

static void
test_fdata(void)
{
#define ASSERT_FDATA(m, wanted) \
	assert((#m " == " #wanted) && !strcmp((s = file_get_metadata(f, (enum MetadataX)m, buf)), wanted));

#define APPEND_FDATA(m, s) \
	assert(0 <= fdata_append(fd, m, s));

	char buf[FILE_METADATAX_BUFSZ];
	char const *s;

	Playlist *playlist = playlist_alloc_master();
	assert(playlist);

	FileData fd[1];
	File f[1];
	f->url = strdup("./a/b");

	fdata_reset_with_url(fd, f->url);
	APPEND_FDATA(M_disc, " 000D / 0DT   ");
	APPEND_FDATA(M_date, " 20000102   ");
	assert(0 <= fdata_write_date(fd, M_artist, 1000000000));
	assert(0 <= fdata_writef(fd, M_title, " %s-%s ", "a", "b"));

	assert(0 <= fdata_save(fd, f));
	assert(playlist->modified);
	playlist->modified = 0;

	ASSERT_FDATA(M_disc, "D");
	ASSERT_FDATA(M_disc_total, "DT");
	ASSERT_FDATA(M_date, "2000-01-02");
	ASSERT_FDATA(M_artist, "2001-09-09");
	ASSERT_FDATA(M_title, " a-b ");

	fdata_reset_with_url(fd, f->url);
	APPEND_FDATA(M_title, "   ");
	APPEND_FDATA(M_artist, "  A   0 ");
	APPEND_FDATA(M_artist, "A1");
	APPEND_FDATA(M_artist, "A2     ");
	APPEND_FDATA(M_disc, " 000D");
	APPEND_FDATA(M_disc_total, " 00DT");
	APPEND_FDATA(M_track_total, "  TT   ");
	APPEND_FDATA(M_date, "2000");
	APPEND_FDATA(M_date, "2001-02");
	APPEND_FDATA(M_date, "  2003-apr-05    ");
	APPEND_FDATA(M_date, "   1999          ");
	APPEND_FDATA(M_track, " 00T/ TTx");

	assert(0 <= fdata_save(fd, f));
	assert(playlist->modified);
	playlist->modified = 0;

	assert(!file_get_metadata(f, (enum MetadataX)M_title, buf));
	ASSERT_FDATA(M_artist, "A 0;A1;A2");
	ASSERT_FDATA(M_disc, "D");
	ASSERT_FDATA(M_disc_total, "DT");
	ASSERT_FDATA(M_track, "T");
	ASSERT_FDATA(M_track_total, "TT");
	ASSERT_FDATA(M_date, "2003-apr-05");

	assert(0 <= fdata_save(fd, f));
	assert(!playlist->modified);

	ASSERT_FDATA(MX_url, "./a/b");
	ASSERT_FDATA(MX_name, "b");
}

static void
test_math(void)
{
	int i = 0;
	assert(MAXMIN(0 * ++i, 1, -2) == 0);
	assert(MAXMIN(0 * ++i, -1, -2) == 0);
	assert(MAXMIN(0 * ++i, 1, 2) == 1);
	assert(MAXMIN(0 * ++i, 3, 2) == 2);
	assert(MAXMIN(0 * ++i, -3, 2) == 0);
	assert(i == 5);
}

int
main()
{
	int i = 0;
	assert(++i);
	if (!i) {
		fprintf(stderr, "Asserts disabled\n");
		abort();
	}

	test_expr();
	test_fdata();
	test_math();
}
