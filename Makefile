# aiven_gatekeeper/Makefile

MODULES = aiven_gatekeeper
PGFILEDESC = "aiven_gatekeeper - guard against privilege escalation attacks in extensions"
OBJS = src/aiven_gatekeeper.o

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
