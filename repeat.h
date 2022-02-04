#ifndef MUCK_REPEAT_H
#define MUCK_REPEAT_H

#define REPEAT1(i) xmacro(i)
/*
read! for i ({1..8}); printf '\#define REPEAT\%1$d(i) REPEAT\%2$d(i) REPEAT\%2$d(\%2$d + i)\n' $(( 2 ** i )) $(( 2 ** i / 2 ))
*/

#define REPEAT2(i) REPEAT1(i) REPEAT1(1 + i)
#define REPEAT4(i) REPEAT2(i) REPEAT2(2 + i)
#define REPEAT8(i) REPEAT4(i) REPEAT4(4 + i)
#define REPEAT16(i) REPEAT8(i) REPEAT8(8 + i)
#define REPEAT32(i) REPEAT16(i) REPEAT16(16 + i)
#define REPEAT64(i) REPEAT32(i) REPEAT32(32 + i)
#define REPEAT128(i) REPEAT64(i) REPEAT64(64 + i)
#define REPEAT256(i) REPEAT128(i) REPEAT128(128 + i)

#endif
