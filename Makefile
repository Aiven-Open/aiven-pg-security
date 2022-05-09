# aiven_gatekeeper/Makefile

MODULES_big = aiven_gatekeeper
PGFILEDESC = "aiven_gatekeeper - guard against privilege escalation attacks in extensions"
OBJS = $(patsubst %.c,%.o,$(wildcard src/*.c))

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
