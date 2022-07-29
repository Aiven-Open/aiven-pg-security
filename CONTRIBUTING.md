# Welcome!

Contributions are very welcome on Aiven Gatekeeper. When contributing please keep this in mind:

- Open an issue to discuss new bigger features.
- Write code consistent with the project style and make sure the tests are passing.
- Stay in touch with us if we have follow up questions or requests for further changes.

# Development

## Local Environment


## Tests
All pull requests are expected to pass the GitHub actions for the various PostgreSQL versions. The agent should
work on all supported versions of PostgreSQL, current v10 - v14.

## Static checking and Linting
The GitHub actions might pass but with warnings. All ISO C90 warnings are expected to be resolved before changes will be accepted.

The build is run with default PostgreSQL make options from pg_config;

```
gcc -Wall -Wmissing-prototypes -Wpointer-arith -Wdeclaration-after-statement -Wendif-labels -Wmissing-format-attribute -Wformat-security -fno-strict-aliasing -fwrapv -fexcess-precision=standard -Wno-format-truncation -Wno-stringop-truncation -g -g -O2 -flto=auto -ffat-lto-objects -flto=auto -ffat-lto-objects -fstack-protector-strong -Wformat -Werror=format-security -fno-omit-frame-pointer -fPIC -Wdate-time -D_FORTIFY_SOURCE=2
```

## Manual testing


### Configuration


# Opening a PR

- Commit messages should describe the changes, not the filenames. Win our admiration by following
  the [excellent advice from Chris Beams](https://chris.beams.io/posts/git-commit/) when composing
  commit messages.
- Choose a meaningful title for your pull request.
- The pull request description should focus on what changed and why.
- Check that the tests pass (and add test coverage for your changes if appropriate).
