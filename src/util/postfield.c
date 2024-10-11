#include <keycloak/util/postfield.h>
#include <str_builder/str_builder.h>

void _keycloak_add_postfield(
  str_builder_t* sb,
  const char* key,
  const char* val
) {
  if (str_builder_len(sb) != 0)
    str_builder_add_str(sb, "&", 0);
  str_builder_add_str(sb, key, 0);
  str_builder_add_str(sb, "=", 0);
  str_builder_add_str(sb, val, 0);
}
