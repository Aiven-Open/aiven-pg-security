# About

The Aiven Security Agent for Postgresql (aiven-gatekeeper) allows controlling which functions are exposed and prevents common privilege escalation attacks.

Aiven provides Postgresql as a Database as a Service (DBaaS). As part of the service offering and hardening of the service, customers are given a privileged user (avnadmin) however the superuser privilege is not given to this user. Superuser access provides the ability to reconfigure the database, something we don't want from a manageability stand-point, and also provides access to functions that allow interaction with the underlying host. Even though all instances are run as single tenant and single host, with additional host hardening applied, providing direct filesystem/host access is not desired.

## Common Privilege Escalation Attacks in Postgresql

Aiven allows customers to use a predefined list of extensions. By default, users require the superuser privilege to create extensions in Postgresql. This poses a problem since the superuser privilege isn't given to customers. To get around this, the pgextwlist extension is used to allow creation of extensions from a lower privileged user. The extension is created using the default superuser, postgres, which now exposes Aiven to the risk of privilege escalation attacks. Should an extension installation script be written in an insecure manner (a very common occurrence), it is possible for users to gain superuser privileges.

## How the agent works
The agent is loaded as a shared library at Postgresql server startup and uses a number of hooking functions to intercept and inspect utility and function calls. A security decision can be made by examining the current execution state and determining if a privileged action should be allowed or not.

The agent uses the following three criteria for making a risk assessment before allowing/disallowing a function call:

**creating_extension**

The function is executing during the `CREATE EXTENSION` function.

**is_elevated**

The execution context is deemed to be "elevated" when the __current_user__ is a superuser but the __session_user__ does not have the superuser privilege. This occurs during `CREATE EXTENSION` or `SECURITY DEFINER` function execution.

**is_security_restricted**

Postgresql can set the current execution context to `SECURITY RESTRICTED` and already limits some of the actions that can be performed during this context. The agent compliments these existing restrictions.

## UtilityProcess_hook

Three primary utility functions are examined by the security agent:

### Role altering/granting

`ALTER/CREATE/GRANT ROLE` - When altering, creating or granting a role with the superuser privilege

Prevents granting the privileged permissions

* pg_read_server_files
* pg_write_server_files
* pg_execute_server_program

### Command Execution

`COPY TO/FROM PROGRAM` - This is normally reserved for the superuser or roles with the pg_execute_server_program permission. This is always blocked, regardless of the context. There is no reason, on the Aiven platform, for execution of underlying host commands from within Postgresql

### File read/write

`COPY TO/FROM FILE` - This functionality is normally reserved for the superuser or roles with the `pg_read_server_files` or `pg_write_server_files` permission. This is blocked during an elevated context. 


## object_access_hook

The object access hook allows the agent to examine a function call and determine if that function should be executed. By using this hook it is possible to monitor sensitive builtin functions, that are normally reserved for superuser (or users who have been granted execute on these functions), and apply the additional security checks.

The hook monitors a predefined list of builtin functions and does not interfere with user defined functions. Currently the following functions have additional checks applied to them;

* pg_read_file
* pg_read_binary_file
* lo_import
* lo_export

## Agent Configuration

The agent is enabled by default on Aiven Postgresql services. The agent can be toggled off by setting the configuration option **aiven.pg_security_agent**. This configuration option can only be set in the __postgresql.conf__ configuration or via the `ALTER SYSTEM` function.
To disable the agent, set `aiven.pg_security_agent = off` in the __postgresql.conf__ and send the `SIGHUP` signal to the postgresql service. You can also restart the service, or as a superuser execute the SQL function `SELECT pg_config_reload()`.

Alternatively execute `ALTER SYSTEM SET aiven.pg_security_agent TO off;` as a superuser and then execute `SELECT pg_config_reload();` to force the reloading of the __postgresql.conf__ configuration.
