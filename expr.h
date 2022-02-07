#ifndef MUCK_EXPR_H
#define MUCK_EXPR_H

#include <stdint.h>

#include "error.h"
#include "file.h"
#include "metadata.h"
#include "regex.h"

typedef struct Expr Expr;

typedef struct {
	Expr *expr;
} UnaryExpr;

typedef struct {
	Expr *lhs;
	Expr *rhs;
} BinaryExpr;

enum {
	EXPR_NUMSZ = 5,
};

typedef struct {
	MetadataSet keys;
	enum KeyOp {
		KOP_RE = 1 << 0,
		KOP_LT = 1 << 1,
		KOP_EQ = 1 << 2,
		KOP_GT = 1 << 3,
		KOP_ISSET = 1 << 4,
	} op;
	union {
		pcre2_code *re;
		struct {
			uint8_t nnums;
			int32_t nums[EXPR_NUMSZ];
		};
	};
} KVExpr;

struct Expr {
	/* In the order of precedence. */
	enum ExprType {
		EXPR_KV,
		EXPR_TRUE,
		EXPR_NEG,
		EXPR_AND,
		EXPR_OR,
		EXPR_GROUP,
	} type;
	Expr *parent;
	union {
		UnaryExpr un;
		BinaryExpr bi;
		KVExpr kv;
	};
};

typedef struct ExprParserContext {
	char const *src;
	char const *ptr;
	File *cur;
	pcre2_match_data *match_data;

	Error error;
} ExprParserContext;

typedef struct {
	File const *f;
	pcre2_match_data *match_data;
} ExprEvalContext;

void expr_global_init(Error *error);
void expr_global_uninit(void);

Expr *expr_alloc(enum ExprType type);
void expr_free(Expr *expr);

Expr *expr_parse(ExprParserContext *parser);
void expr_optimize(Expr **pexpr);
int expr_eval(Expr const *expr, ExprEvalContext const *ctx);

int expr_depends_key(Expr const *expr, enum MetadataX m);

char const *expr_strtoi(char const *s, int32_t *ret);

#endif
