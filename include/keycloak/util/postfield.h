#ifndef _KEYCLOAK_POSTFIELD_H
#define _KEYCLOAK_POSTFIELD_H

#include <str_builder/str_builder.h>

void _keycloak_add_postfield(
  str_builder_t* sb,
  const char* key,
  const char* val
);

#endif
