# aiven_gatekeeper/Makefile

EXTENSION = aiven_gatekeeper
MODULES_big = aiven_gatekeeper
PGFILEDESC = "aiven_gatekeeper - guard against privilege escalation attacks in extensions"
OBJS = aiven_gatekeeper.o

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
