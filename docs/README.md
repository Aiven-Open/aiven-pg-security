# About

The Aiven Security Agent for PostgreSQL® (aiven-gatekeeper) allows controlling which privileged functions are exposed and prevents their abuse in common privilege escalation attacks.

Aiven provides PostgreSQL as a Database as a Service (DBaaS). As part of the service offering, customers are given a privileged user (avnadmin), however the superuser privilege is not given to this user. Superuser access allows bypassing all permission checks, and provides the ability to reconfigure the database, something we don't want from a manageability stand-point. Superuser also provides access to functions that allow interaction, reading files and executing programs, on the underlying host. A database is useful, but can be made even more useful through extensions. PostgreSQL supports a plethora of useful extensions and we in turn want to ensure our customers can use those extensions. Unfortunately, due to the design of PostgreSQL, most extensions require elevated (superuser) permissions to be installed. This creates a security conundrum, how to allow customers to install extensions without superuser access?

## How the agent works
The agent is loaded as a shared library at PostgreSQL server startup and uses a number of hooking functions to intercept and inspect utility and function calls. A security decision can be made by examining the current execution state and determining if a privileged action should be allowed or not.

The agent uses the following three criteria for making a risk assessment before allowing/disallowing a function call:

**creating_extension**

The function is executing during the `CREATE EXTENSION` transaction.

**is_elevated**

The execution context is deemed to be "elevated" when the __current_user__ is a superuser but the __session_user__ does not have the superuser privilege. This occurs during `CREATE EXTENSION` or `SECURITY DEFINER` function execution.

**is_security_restricted**

PostgreSQL can set the current execution context to `SECURITY RESTRICTED` and already limits some of the actions that can be performed during this context. The agent compliments these existing restrictions.

## UtilityProcess_hook

Three primary utility functions are examined by the security agent:

### Role altering/granting

`ALTER/CREATE/GRANT ROLE` - When altering, creating or granting a role with the superuser privilege

Prevents granting the privileged permissions

* pg_read_server_files
* pg_write_server_files
* pg_execute_server_program

### Command Execution

`COPY TO/FROM PROGRAM` - This is normally reserved for the superuser or roles with the pg_execute_server_program permission. This is always blocked, regardless of the context. There is no reason, on the Aiven platform, for execution of underlying host commands from within PostgreSQL

### File read/write

`COPY TO/FROM FILE` - This functionality is normally reserved for the superuser or roles with the `pg_read_server_files` or `pg_write_server_files` permission. This is blocked during an elevated context.


## object_access_hook

The object access hook allows the agent to examine a function call and determine if that function should be executed. By using this hook it is possible to monitor sensitive builtin functions, that are normally reserved for superuser (or users who have been granted execute on these functions), and apply the additional security checks.

The hook monitors a predefined list of builtin functions and does not interfere with user defined functions. Currently the following functions have additional checks applied to them;

* pg_read_file
* pg_read_binary_file
* pg_reload_conf
* lo_import
* lo_export

## System tables

The agent prevents modification to some system tables, namely `pg_proc` and `pg_authid`. This helps prevent modifications that could bypass the other protections offered by the agent.

## Agent Configuration

The agent is enabled by default on Aiven PostgreSQL services. The agent can be toggled off by setting the configuration option **aiven.pg_security_agent**. This configuration option can only be set in the __postgresql.conf__ configuration or via the `ALTER SYSTEM` function.
To disable the agent, set `aiven.pg_security_agent = off` in the __postgresql.conf__ and send the `SIGHUP` signal to the postgresql service. You can also restart the service, or as a superuser execute the SQL function `SELECT pg_config_reload()`.

Alternatively execute `ALTER SYSTEM SET aiven.pg_security_agent TO off;` as a superuser and then execute `SELECT pg_config_reload();` to force the reloading of the __postgresql.conf__ configuration.


## Strict mode

The agent can be set to strict mode, where the usual checks apply in all context. This means actions that are normally only blocked in "elevated contexts" will also be blocked for any superuser session.

To enable strict mode, set `aiven.pg_security_agent_strict = on` in __postgresql.conf__. Once set, postmaster needs to be restarted. With strict mode enabled, it is not possible for the superuser to disable the agent via a `pg_config_reload`. If `ALTER SYSTEM SET aiven.pg_security_agent_strict TO on;` was used to enable strict mode, the setting needs to be changed or removed from __postgresql.auto.conf__ before restarting postmaster (the setting in .auto. will override that in __postgresql.conf__).
