Coding guidelines for s390-tools
================================

For s390-tools the preferred language is C. We provide libraries, e.g.
[`libutil`](libutil) that should be used by all tools if possible.

The coding style is based on the Linux [kernel guidelines]. Therefore, use
the [checkpatch] tool for verification before you submit a patch.

[kernel guidelines]: https://www.kernel.org/doc/html/latest/process/coding-style.html
[checkpatch]: https://github.com/torvalds/linux/blob/master/scripts/checkpatch.pl

Below we describe some additional things that we want you to consider when
writing new code for s390-tools.

This package started in 2001 and has a long "tradition" - therefore, older tools
might not follow all recommendations. Note that when changing existing code,
consistency could have priority over applying rules.

Automatic Code Formatting
-------------------------

> **NOTE:** clang-format is a helpful tool but please don't use it blindly!

s390-tools provides a ClangFormat (https://clang.llvm.org/docs/ClangFormat.html)
configuration file - see [`.clang-format`](.clang-format). It can be used to
format your C/C++ code automatically.

Clang-format can format a single file or multiple files at once. For example, to
format `main.c` in place, run the following command in a terminal:

```bash
clang-format -i main.c
```

In order to format only your current staged changes use the clang-format git
plugin:

```bash
git clang-format --staged
```

See also `git clang-format -h`.

Standard abbreviations
----------------------

The abbreviations below are recommended to be used in the source code.

| __Short Name__  | __Long Name__                                     |
|:----------------|:--------------------------------------------------|
| attr            | Attribute                                         |
| blk             | Block                                             |
| buf             | Buffer                                            |
| col             | Column                                            |
| count           | Count                                             |
| desc            | Description                                       |
| dir             | Directory                                         |
| fd              | File descriptor (open)                            |
| fp              | File pointer (fopen)                              |
| len             | Length                                            |
| lib             | Library                                           |
| mod             | Module                                            |
| nr              | Number                                            |
| parm            | Parameter                                         |
| path            | File path                                         |
| ptr             | Pointer                                           |
| rc              | Return code                                       |
| size            | Size                                              |
| src             | Source                                            |
| str             | String                                            |
| sym             | Symbol                                            |
