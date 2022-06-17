Aiven PostgreSQL Security
======================
Adds utility functions to harden PostgreSQL through shared libraries and hooks.

Overview
========
The Aiven Security Agent for Postgresql (aiven-gatekeeper) allows controlling which functions are exposed and prevents common privilege escalation attacks.

Features
============
Prevents common privilege escalation attacks, primarily at the time of extension creation. Limits access to sensitive features and functions within Postgresql and compliments the existing grants and superuser checks.

Setup
============

Build and install the add on
```
$ make
$ cp aiven_gatekeeper.so $postgres_lib/

# edit postgresql.conf
shared_preload_libraries = 'aiven_gatekeeper'

# restart postgresql
```

License
============
Aiven PostgreSQL Security is licensed under the Apache license, version 2.0. Full license text is available in the [LICENSE](LICENSE) file.

Please note that the project explicitly does not require a CLA (Contributor License Agreement) from its contributors.

Contact
============
Bug reports and patches are very welcome, please post them as GitHub issues and pull requests at https://github.com/aiven/aiven-pg-security . 
To report any possible vulnerabilities or other serious issues please see our [security](SECURITY.md) policy.
