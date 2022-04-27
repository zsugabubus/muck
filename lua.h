#ifndef MUCK_LUA_H
#define MUCK_LUA_H

void l_open(void);
void l_destroy(void);

int l_hook_on_key(char const *key);
int l_hook_on_eof(void);

#endif
