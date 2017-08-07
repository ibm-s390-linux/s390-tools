Contributing to s390-tools
==========================

License
-------
All contributions have to be submitted under the MIT license. See also
the [LICENSE](LICENSE) file.

Developer's Certificate of Origin and Signed-off-by
---------------------------------------------------
The sign-off is a simple line at the end of the explanation for the patch,
which certifies that you wrote it or otherwise have the right to pass it on as
an open-source patch.

With the Signed-off-by line you certify the below:

```
Developer's Certificate of Origin 1.1

       By making a contribution to this project, I certify that:

       (a) The contribution was created in whole or in part by me and I
           have the right to submit it under the open source license
           indicated in the file; or

       (b) The contribution is based upon previous work that, to the best
           of my knowledge, is covered under an appropriate open source
           license and I have the right under that license to submit that
           work with modifications, whether created in whole or in part
           by me, under the same open source license (unless I am
           permitted to submit under a different license), as indicated
           in the file; or

       (c) The contribution was provided directly to me by some other
           person who certified (a), (b) or (c) and I have not modified
           it.

       (d) I understand and agree that this project and the contribution
           are public and that a record of the contribution (including all
           personal information I submit with it, including my sign-off) is
           maintained indefinitely and may be redistributed consistent with
           this project or the open source license(s) involved.
```

If you can certify the above, just add a line saying:

```
Signed-off-by: Random Developer <random@developer.example.org>
```

Please use your real name (no pseudonyms or anonymous contributions).

Submitting code
---------------
The preferred way is to create a github pull request for your code.

Coding guidelines
-----------------
For s390-tools the preferred language is C. We provide libraries, e.g. libutil
that should be used by all tools if possible.

The coding style is based on the Linux kernel guidelines. Therefore, use
the checkpatch tool [1] for verification before you submit a patch.

[1] https://github.com/torvalds/linux/blob/master/scripts/checkpatch.pl
