Aiven PG Security Utility
======================
Adds utility functions to harden PostgreSQL® through shared libraries and hooks.

See our blog post about aiven-gatekeeper and PostgreSQL extension security: [Aiven's Blog](https://aiven.io/blog/aiven-security-agent-for-postgresql).

Overview
========
The Aiven Security Agent for PostgreSQL (aiven-gatekeeper) allows controlling which privileged functions are exposed and prevents their abuse in common privilege escalation attacks.

Features
============
Prevents common privilege escalation attacks, primarily at the time of extension creation. Limits access to sensitive features and functions within PostgreSQL and compliments the existing grants and superuser checks.

For detailed features and how they work, visit the [documentation](docs/).

Security
===========
An independent, external code audit was performed and the results are available in the [docs](docs/) directory:
* [Report letter](docs/20220805%20Aiven%20Customer%20Letter.pdf)
* [Final report](docs/20220805%20Aiven%20Oy%20-%20Aiven%20Source%20Code%20Audit%20Retest%20Final%20Report.pdf)

To report any possible vulnerabilities or other serious issues please see our [security](SECURITY.md) policy.

Setup
============

Build and install the add on;
```bash
$ make
$ cp aiven_gatekeeper.so $postgres_lib/

# or make and install
$ make install

```
Configure PostgreSQL to use the library;
```bash
# edit your postgresql.conf and load the library
shared_preload_libraries = 'aiven_gatekeeper'

# restart postgresql
```

License
============
Aiven PostgreSQL Security is licensed under the PostgreSQL license. Full license text is available in the [LICENSE](LICENSE) file.

Please note that the project explicitly does not require a CLA (Contributor License Agreement) from its contributors.

Contact
============
Bug reports and patches are very welcome, please post them as GitHub issues and pull requests at https://github.com/aiven/aiven-pg-security .
To report any possible vulnerabilities or other serious issues please see our [security](SECURITY.md) policy.

Trademarks
============
The terms Postgres and PostgreSQL are registered trademarks of the PostgreSQL Community Association of Canada.
