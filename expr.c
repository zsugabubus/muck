#include "compat/string.h"
#include "math_utils.h"
#include <assert.h>
#include <errno.h>

#include "expr.h"

static char const ERR_UNEXPECTED_END[] = "Unexpected end of input";
static char const ERR_EXPRESSION_EXPECTED[] = "Expression expected";
static char const ERR_STRAY_CLOSE[] = "Stray )";
static char const ERR_UNKNOWN_KEY[] = "Unknown key";
static char const ERR_NO_CURRENT_FILE[] = "No current file";
static char const ERR_TOO_LONG[] = "Too long";

static pcre2_code *re_ucase;

#define EXPR_ITER_ENTER_NODE \
	Expr *parent = NULL; \
	enter:;
#define EXPR_ITER_LEAVE_NODE \
	switch (expr->type) { \
	case EXPR_NEG: \
	case EXPR_GROUP: \
		expr = expr->un.expr; \
		goto enter; \
 \
	case EXPR_AND: \
	case EXPR_OR: \
		expr = expr->bi.lhs; \
		goto enter; \
 \
	case EXPR_KV: \
	case EXPR_TRUE: \
		goto leave; \
 \
	default: \
		abort(); \
	} \
leave:; \
	parent = expr->parent;
#define EXPR_ITER_END \
	if (parent) switch (parent->type) { \
	case EXPR_AND: \
	case EXPR_OR: \
		if (expr != parent->bi.rhs) { \
			expr = parent->bi.rhs; \
			goto enter; \
		} \
		goto leave_parent; \
 \
	default: \
	leave_parent:; \
		expr = parent; \
		goto leave; \
	}

void
expr_global_init(Error *error)
{
	size_t error_offset;
	int error_code;
	re_ucase = pcre2_compile(
			(uint8_t const[]){ "\\p{Lu}" }, 6,
			PCRE2_UTF | PCRE2_NO_UTF_CHECK,
			&error_code, &error_offset,
			NULL);
	if (!re_ucase)
		error_from_regerror(error, error_code);
}

void
expr_global_uninit(void)
{
	pcre2_code_free(re_ucase);
}

char const *
expr_strtoi(char const *s, int32_t *ret)
{
	while (*s && !('0' <= *s && *s <= '9'))
		++s;
	if (!*s)
		return NULL;

	int32_t n = 0;
	do
		n = 10 * n + (*s++ - '0');
	while ('0' <= *s && *s <= '9');

	/* Units. */
	if ('m' == *s)
		n *= 60;

	*ret = n;
	return s;
}

static int
expr_eval_kv_key(Expr const *expr, enum MetadataX m, ExprEvalContext const *ctx)
{
	char buf[FILE_METADATAX_BUFSZ];
	char const *value = file_get_metadata(ctx->f, m, buf);

	/* Fallback to the URL if metadata is missing for this
	 * file. This way user can avoid nasty queries in a new
	 * playlist. */
	if (!value &&
	    !(KOP_ISSET & expr->kv.op) &&
	    (METADATASET_IN_URL & metadata_to_set(m)) &&
	    !ctx->f->metadata[M_length])
		value = ctx->f->url;
	else if (!value)
		return 0;

	if (KOP_RE & expr->kv.op) {
		for (char const *s = value;;) {
			char *end = strchrnul(s, ';');

			int rc = pcre2_match(expr->kv.re,
					(uint8_t const *)s,
					end - s,
					0, 0, ctx->match_data, NULL);
			if (0 <= rc)
				return 1;
			assert(PCRE2_ERROR_NOMATCH == rc);

			if (!*end)
				return 0;
			s = end + 1;
		}
	} else {
		char const *s = value;
		for (uint8_t i = 0;;) {
			if (expr->kv.nnums <= i)
				return 1;

			int32_t vn;
			if (!(s = expr_strtoi(s, &vn)))
				return 0;

			int32_t n = expr->kv.nums[i++];
			enum KeyOp rel = KOP_LT << ((vn > n) - (vn < n) + 1);
			if (rel & ~KOP_EQ & expr->kv.op)
				return 1;
			if (rel & ~expr->kv.op)
				return 0;
		}
	}
}

int
expr_eval(Expr const *expr, ExprEvalContext const *ctx)
{
	int ret = 1;

	EXPR_ITER_ENTER_NODE;
	EXPR_ITER_LEAVE_NODE;
	switch (expr->type) {
	case EXPR_KV:
		ret = 0;
		for each_metadata(m, expr->kv.keys) {
			if (expr_eval_kv_key(expr, m, ctx)) {
				ret = 1;
				break;
			}
		}
		break;

	case EXPR_TRUE:
		ret = 1;
		break;

	case EXPR_NEG:
		ret = !ret;
		break;

	default:
		/* Not terminal. */
		break;
	}

	if (parent) switch (parent->type) {
	case EXPR_AND:
		if (!ret)
			goto leave_parent;
		break;

	case EXPR_OR:
		if (ret)
			goto leave_parent;
		break;

	default:
		/* No short circuiting. */
		break;
	}

	EXPR_ITER_END;

	return ret;
}

void
expr_free(Expr *expr)
{
	if (expr)
		expr->parent = NULL;

	EXPR_ITER_ENTER_NODE;
	if (!expr)
		goto leave_child;

	EXPR_ITER_LEAVE_NODE;
	if (EXPR_KV == expr->type) {
		if (KOP_RE & expr->kv.op)
			pcre2_code_free(expr->kv.re);
	}
	free(expr);

leave_child:
	EXPR_ITER_END;
}

Expr *
expr_alloc(enum ExprType type)
{
#define EXPR_sizeof(u) (offsetof(Expr, u) + sizeof ((Expr *)0)->u)

	static size_t const EXPR_SZ[] = {
		[EXPR_KV] = EXPR_sizeof(kv),
		[EXPR_TRUE] = EXPR_sizeof(parent),
		[EXPR_NEG] = EXPR_sizeof(un),
		[EXPR_AND] = EXPR_sizeof(bi),
		[EXPR_OR] = EXPR_sizeof(bi),
		[EXPR_GROUP] = EXPR_sizeof(un),
	};

#undef EXPR_sizeof

	Expr *expr = calloc(1, EXPR_SZ[type]);
	if (expr)
		expr->type = type;
	return expr;
}

static Expr *
expr_parse_kv(ExprParserContext *parser)
{
	Expr *expr = expr_alloc(EXPR_KV);
	if (!expr)
		return NULL;

	expr->kv.keys = 0;
	while (('a' <= *parser->ptr && *parser->ptr <= 'z') ||
	       ('A' <= *parser->ptr && *parser->ptr <= 'Z'))
	{
		enum MetadataX m;
		if (!metadata_parse(&m, *parser->ptr)) {
			parser->error.msg = ERR_UNKNOWN_KEY;
			goto fail;
		}
		++parser->ptr;

		expr->kv.keys |= metadata_to_set(m);
	}
	if (!expr->kv.keys)
		expr->kv.keys = METADATASET_IN_URL;

	if ('?' == *parser->ptr) {
		++parser->ptr;
		expr->kv.op |= KOP_ISSET;
	}

	switch (*parser->ptr) {
	case '~':
		++parser->ptr;
		/* FALLTHROUGH */
	default:
		expr->kv.op |= KOP_RE;
		break;

	case '<':
		++parser->ptr;
		expr->kv.op |= KOP_LT;
		goto may_eq;

	case '>':
		++parser->ptr;
		expr->kv.op |= KOP_GT;
		goto may_eq;

	may_eq:
		if ('=' == *parser->ptr) {
	case '=':
			++parser->ptr;
			expr->kv.op |= KOP_EQ;
		}
		break;
	}

	char const *p = parser->ptr;

	char buf[1 << 12]; /* TODO: Make it heap allocated. */
	size_t bufsz = 0;
	char st = '"' == *p || '\'' == *p ? *p++ : '\0';

	for (; *p && (st ? st != *p : ' ' != *p && '|' != *p && ')' != *p); ++p) {
		unsigned magic_sp = 0;
		if (' ' == *p) {
			unsigned escaped = 0;
			for (size_t i = bufsz; 0 < i && '\\' == buf[--i];)
				escaped ^= 1;
			magic_sp = !escaped;
		}

		if (magic_sp) {
			if (sizeof buf - 1 /* NUL */ - 6 < bufsz)
				goto fail_too_long;
			memcpy(buf + bufsz, "[._ -]", 6);
			bufsz += 6;
		} else {
			if (sizeof buf - 1 /* NUL */ - 1 < bufsz)
				goto fail_too_long;
			buf[bufsz++] = *p;
		}
	}

	uint32_t re_flags = PCRE2_UTF | PCRE2_MATCH_INVALID_UTF;
	if (!bufsz) {
		re_flags |= PCRE2_LITERAL;

		File const *cur = parser->cur;
		if (!cur) {
			parser->error.msg = ERR_NO_CURRENT_FILE;
			goto fail;
		}

		for each_metadata(m, expr->kv.keys) {
			char mbuf[FILE_METADATAX_BUFSZ];
			char const *value = file_get_metadata(cur, m, mbuf);
			if (!value)
				continue;

			while (*value && ';' != *value) {
				if (sizeof buf - 1 /* NUL */ - 1 < bufsz)
					goto fail_too_long;
				buf[bufsz++] = *value++;
			}
		}
	} else {
		re_flags |= PCRE2_DOTALL;
	}

	buf[bufsz] = '\0';

	if (KOP_RE & expr->kv.op) {
		int rc = pcre2_match(re_ucase,
				(uint8_t const *)buf, bufsz, 0,
				0, parser->match_data, NULL);
		if (rc < 0) {
			assert(PCRE2_ERROR_NOMATCH == rc);
			re_flags |= PCRE2_CASELESS;
		}

		size_t error_offset;
		int error_code;
		expr->kv.re = pcre2_compile(
				(uint8_t const *)buf, bufsz, re_flags,
				&error_code, &error_offset, NULL);
		if (!expr->kv.re) {
			error_from_regerror(&parser->error, error_code);
			goto fail;
		}

		(void)pcre2_jit_compile(expr->kv.re, PCRE2_JIT_COMPLETE);
	} else {
		char const *s = buf;
		expr->kv.nnums = 0;
		for (;;) {
			if (EXPR_NUMSZ <= expr->kv.nnums) {
				parser->error.msg = ERR_TOO_LONG;
				goto fail;
			}

			if (!(s = expr_strtoi(s, &expr->kv.nums[expr->kv.nnums])))
				break;
			++expr->kv.nnums;
		}
	}

	if (*p && st)
		++p;

	parser->ptr = p;
	return expr;

fail_too_long:
	parser->error.msg = ERR_TOO_LONG;
fail:
	assert(!error_is_ok(&parser->error));
	expr_free(expr);
	return NULL;
}

static uint32_t
expr_cost(Expr *expr)
{
	uint32_t cost = 0;
	Expr *root = expr;

	EXPR_ITER_ENTER_NODE;
	EXPR_ITER_LEAVE_NODE;
	switch (expr->type) {
	case EXPR_TRUE:
	case EXPR_GROUP:
		/* No cost. */
		break;

	case EXPR_KV:
		if (KOP_RE & expr->kv.op)
			cost +=
				1000 * __builtin_popcount(expr->kv.keys & METADATASET_NOT_X) +
				/* Expect extended keys to be more unique. */
				10 * __builtin_popcount(expr->kv.keys & METADATASET_IS_X);
		else
			cost += 100;
		break;

	case EXPR_NEG:
		cost += 1;
		break;

	case EXPR_AND:
	case EXPR_OR:
		cost += 2;
		break;

	default:
		abort();
	}
	if (expr != root)
		EXPR_ITER_END;
	return cost;
}

int
expr_depends_key(Expr const *expr, enum MetadataX m)
{
	if (!expr)
		return 0;

	EXPR_ITER_ENTER_NODE;
	if (EXPR_KV == expr->type)
		if (expr->kv.keys & metadata_to_set(m))
			return 1;

	EXPR_ITER_LEAVE_NODE;
	EXPR_ITER_END;

	return 0;
}

static Expr **
expr_get_parent_loc(Expr const *expr)
{
	Expr *parent = expr->parent;
	switch (parent->type) {
	case EXPR_GROUP:
	case EXPR_NEG:
		return &parent->un.expr;

	case EXPR_AND:
	case EXPR_OR:
		return expr == parent->bi.lhs
			? &parent->bi.lhs
			: &parent->bi.rhs;

	case EXPR_KV:
	case EXPR_TRUE:
	default:
		abort();
	}
}

/* *pexpr := *pdescendant */
static void
expr_replace(Expr **pexpr, Expr **pdescendant)
{
	Expr *expr = *pexpr;
	Expr *parent = expr->parent;
	if (parent)
		*expr_get_parent_loc(expr) = *pdescendant;
	(*pexpr = *pdescendant)->parent = parent;
	*pdescendant = NULL;
	expr_free(expr);
}

void
expr_optimize(Expr **proot)
{
	Expr *expr = *proot;

	EXPR_ITER_ENTER_NODE;
	EXPR_ITER_LEAVE_NODE;
	switch (expr->type) {
	case EXPR_GROUP:
		expr_replace(&expr, &expr->un.expr);
		break;

	case EXPR_NEG:
		/* Eliminate double negation. */
		if (EXPR_NEG == expr->un.expr->type)
			expr_replace(&expr, &expr->un.expr->un.expr);
		break;

	case EXPR_AND:
	case EXPR_OR:
		/* X AND TRUE, TRUE AND X => X */
		if (EXPR_AND == expr->type) {
			if (EXPR_TRUE == expr->bi.lhs->type) {
				expr_replace(&expr, &expr->bi.rhs);
				break;
			} else if (EXPR_TRUE == expr->bi.rhs->type) {
				expr_replace(&expr, &expr->bi.lhs);
				break;
			}
		}
		/* X OR TRUE, TRUE OR X => TRUE */
		else {
			if (EXPR_TRUE == expr->bi.lhs->type) {
				expr_replace(&expr, &expr->bi.lhs);
				break;
			} else if (EXPR_TRUE == expr->bi.rhs->type) {
				expr_replace(&expr, &expr->bi.rhs);
				break;
			}
		}

		/* Commutative => evaluate cheaper->expensive. */
		if (expr->type == expr->bi.rhs->type) {
			/*
			 *            (*)
			 *   E         E
			 * A   R     R   C
			 *    B C   A B
			 *
			 * (*) is handled below, do not have to care about
			 * it.
			 */
			Expr *r = expr->bi.rhs;
			Expr **b = &r->bi.lhs;
			Expr **a = &expr->bi.lhs;
			if (expr_cost(*a) > expr_cost(*b)) {
				/*
				 *   E
				 * B   R
				 *    A C
				 */
				SWAP(Expr *, *a, *b);
				SWAP(Expr **, a, b);
				(*b)->parent = expr;
				(*a)->parent = r;

				/* Re-optimize after change. */
				parent = expr;
				expr = r;
				goto enter;
			}
		} else if (expr_cost(expr->bi.lhs) > expr_cost(expr->bi.rhs)) {
			SWAP(Expr *, expr->bi.lhs, expr->bi.rhs);
		}
		break;

	case EXPR_KV:
	case EXPR_TRUE:
		/* Nothing to do. */
		break;

	default:
		abort();
	}

	EXPR_ITER_END;

	*proot = expr;
}

static int
expr_is_terminated(Expr const *expr)
{
	switch (expr->type) {
	case EXPR_GROUP:
	case EXPR_NEG:
		return !!expr->un.expr;

	case EXPR_AND:
	case EXPR_OR:
		return !!expr->bi.rhs;

	default:
		return 1;
	}
}

static int
expr_is_stronger(Expr const *left, Expr const *right)
{
	return left->type < right->type;
}

/*
 * INPUT := EPSILON | EXPR
 * EXPR := KV-EXPR
 * EXPR := UNOP EXPR
 * EXPR := EXPR BIOP EXPR
 * EXPR := ( EXPR )
 */
Expr *
expr_parse(ExprParserContext *parser)
{
	Expr *tree = NULL, *cur = NULL;

	tree = expr_alloc(EXPR_GROUP);
	if (!tree)
		goto fail_errno;

	for (;;) {
		switch (*parser->ptr) {
		case '\0':
			/* Auto-close parenthesis, if needed. */
			while (expr_is_terminated(tree)) {
				if (!tree->parent)
					return tree;
				tree = tree->parent;
			}

			/* Allow top-level group to be empty. */
			if (!tree->parent) {
				tree->un.expr = expr_alloc(EXPR_TRUE);
				if (!tree->un.expr)
					goto fail_errno;
				tree->un.expr->parent = tree;
				return tree;
			}

			parser->error.msg = ERR_UNEXPECTED_END;
			goto fail;

		case ' ':
		case '\t':
		case '\r':
		case '\n':
			++parser->ptr;
			continue;

		case '!':
			cur = expr_alloc(EXPR_NEG);
			if (!cur)
				goto fail_errno;
			++parser->ptr;
			break;

		case '&':
		case '|':
			cur = expr_alloc('&' == *parser->ptr ? EXPR_AND : EXPR_OR);
			if (!cur)
				goto fail_errno;
			++parser->ptr;
			break;

		case '(':
			cur = expr_alloc(EXPR_GROUP);
			if (!cur)
				goto fail_errno;
			++parser->ptr;
			break;

		case ')':
			if (!expr_is_terminated(tree)) {
				parser->error.msg = ERR_EXPRESSION_EXPECTED;
				goto fail;
			}
			while (EXPR_GROUP != tree->type)
				tree = tree->parent;
			/* Step out of group. */
			tree = tree->parent;
			if (!tree) {
				parser->error.msg = ERR_STRAY_CLOSE;
				goto fail;
			}
			++parser->ptr;
			continue;

		default:
			cur = expr_parse_kv(parser);
			if (!cur)
				goto fail;
		}

		Expr **lcur;
		switch (cur->type) {
		case EXPR_GROUP:
		case EXPR_NEG:
		case EXPR_KV:
			lcur = NULL;
			break;

		case EXPR_AND:
		case EXPR_OR:
			lcur = &cur->bi.lhs;
			break;

		default:
			abort();
		}

		if (lcur)
			while (expr_is_stronger(tree, cur)) {
				if (!expr_is_terminated(tree)) {
				fail_expr_expected:
					/* Back to the start of the token. They
					 * all have only a single letter so it
					 * is easy. */
					--parser->ptr;
					parser->error.msg = ERR_EXPRESSION_EXPECTED;
					goto fail;
				}
				tree = tree->parent;
			}

		Expr **rtree;
		switch (tree->type) {
		case EXPR_GROUP:
		case EXPR_NEG:
			rtree = &tree->un.expr;
			break;

		case EXPR_AND:
		case EXPR_OR:
			rtree = &tree->bi.rhs;
			break;

		case EXPR_KV:
			rtree = NULL;
			break;

		default:
			abort();
		}

		if (!lcur && (rtree && *rtree)) {
			/*
			 *  T      T
			 * X Y -> X &
			 *         Y C
			 */
			Expr *tmp = expr_alloc(EXPR_AND);
			if (!tmp)
				goto fail_errno;
			while (tree->parent && expr_is_stronger(tree->parent, tmp))
				tree = tree->parent;

			tmp->parent = tree;
			(tmp->bi.lhs = *rtree)->parent = tmp;
			(tmp->bi.rhs = cur)->parent = tmp;
			*rtree = tmp;
		} else if (!lcur && rtree) {
			/*
			 *  T      T
			 * X 0 -> X C
			 */
			(*rtree = cur)->parent = tree;
		} else if (!lcur) {
			/*
			 * T ->  &
			 *      T C
			 */
			Expr *tmp = expr_alloc(EXPR_AND);
			if (!tmp)
				goto fail_errno;
			while (tree->parent && expr_is_stronger(tree->parent, tmp))
				tree = tree->parent;

			*expr_get_parent_loc(tree) = tmp;
			tmp->parent = tree->parent;
			(tmp->bi.lhs = tree)->parent = tmp;
			(tmp->bi.rhs = cur)->parent = tmp;
		} else if (rtree) {
			if (!*rtree)
				goto fail_expr_expected;
			/* stRong C(weak)
			 *   T             T
			 * L   R   C     L   C
			 *    X Y    ->     R
			 *                 X Y
			 */
			cur->parent = tree;
			(*lcur = *rtree)->parent = cur;
			*rtree = cur;
		} else {
			/*
			 * T ->  C
			 *      T 0
			 */
			*expr_get_parent_loc(tree) = cur;
			cur->parent = tree;
			(*lcur = tree)->parent = cur;
		}
		tree = cur;
		cur = NULL;
	}
	abort();

fail_errno:
	error_from_errno(&parser->error);
fail:
	assert(!error_is_ok(&parser->error));
	expr_free(tree);
	expr_free(cur);
	return NULL;
}
