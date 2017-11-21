Coding guidelines for s390-tools
================================

For s390-tools the preferred language is C. We provide libraries, e.g.
[`libutil`](libutil) that should be used by all tools if possible.

The coding style is based on the Linux kernel guidelines. Therefore, use
the checkpatch tool for verification before you submit a patch:

 - https://github.com/torvalds/linux/blob/master/scripts/checkpatch.pl

Below we describe some additional things that we want you to consider when
writing new code for s390-tools.

This package started in 2001 and has a long "tradition" - therefore, older tools
might not follow all recommendations. Note that when changing existing code,
consistency could have priority over applying rules.

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
