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

If you can certify the above, just add a line stating the following at the
bottom of each of your commit messages:

```
Signed-off-by: Random Developer <random@developer.example.org>
```

Please use your real name and a valid e-mail address (no pseudonyms or anonymous
contributions).

Submitting code
---------------
The preferred way is to create GitHub pull requests for your code contributions.
Please create separate pull requests for each logical enhancement, new feature,
or fix.

Before you submit your code please consider our recommendations in the
[CODINGSTYLE](CODINGSTYLE.md) document.

GitHub workflow for contributions
---------------------------------
In the examples below we use this fictive identity:

 - Name: Random Developer
 - E-mail: random@developer.example.org
 - GitHub ID: random-developer

### Setup GitHub and local git

1. Create a fork of this repository by clicking the `Fork` button on the top
   right of the [s390-tools](https://github.com/ibm-s390-linux/s390-tools)
   main page

2. Clone your forked repository to your local development system
   ```
   $ git clone https://github.com/random-developer/s390-tools.git
   ```

3. Configure a remote called "upstream" pointing to the official
   s390-tools repository on GitHub
   ```
   $ cd s390-tools
   ~/s390-tools $ git remote add upstream https://github.com/ibm-s390-linux/s390-tools.git
   ```

4. Verify your remotes
   ```
   ~/s390-tools $ git remote -v
   origin  https://github.com/random-developer/s390-tools.git (fetch)
   origin  https://github.com/random-developer/s390-tools.git (push)
   upstream        https://github.com/ibm-s390-linux/s390-tools.git (fetch)
   upstream        https://github.com/ibm-s390-linux/s390-tools.git (push)
   ```
   You now have two remotes: The "origin" remote points to your fork
   and the "upstream" remote to the official s390-tools repository.

5. Configure your git user name and e-mail
   ```
   ~/s390-tools $ git config user.name "Random Developer"
   ~/s390-tools $ git config user.email "random@developer.example.com"
   ```

### Create a pull request

1. Create and checkout a new branch for your contribution
   ```
   ~/s390-tools $ git checkout -b contrib-doc-pr
   ```

2. Make your changes to the code
   ```
   ~/s390-tools $ vim CONTRIBUTING.md
   ```

3. Build and test your contribution
   ```
   ~/s390-tools $ make clean all
   ~/s390-tools $ # Whatever you have to do for testing
   ```

4. Commit your changes
   ```
   ~/s390-tools $ git add CONTRIBUTING.md
   ~/s390-tools $ git commit -s
   ```

   Provide a meaningful commit message including your "Signed-off-by" line to
   each commit:
   ```
   CONTRIBUTING: Outline steps to submit code

   Explain in more detail how to submit s390-tools contributions as GitHub
   pull requests.

   Signed-off-by: Random Developer <random@developer.example.com>
   ```

5. Use the [checkpatch] tool to validate your commits
   ```
   ~/s390-tools $ checkpatch.pl --no-tree --git master..HEAD
   ```

   Interpret the checkpatch messages wisely - e.g. the 80 character rule can be
   ignored for printf format strings.

   [checkpatch]: https://github.com/torvalds/linux/blob/master/scripts/checkpatch.pl

6. Push the changes to your fork of the repository
   ```
   ~/s390-tools $ git push origin contrib-doc-pr
   ```

7. Go to the GitHub website of your s390-tools fork and create a pull request
   for your branch "contrib-doc-pr"

### Update a pull request during review

If there are changes requested during the review process, you have to update
your code in the pull request.

To retain the existing review comments, add commits on top of your pull request
branch. Depending on the size and number of changes, a rebase of the pull
request might be required. This will be communicated during the review.

1. Update your code with new commits
   ```
   ~/s390-tools $ vi CONTRIBUTING.md
   ~/s390-tools $ git add CONTRIBUTING.md
   ~/s390-tools $ git commit -s -m "CONTRIBUTING: Add update PR info"
   ```

2. Update your pull request by pushing changes
   ```
   ~/s390-tools $ git push origin contrib-doc-pr
   ```

### Finalize a pull request

After the review process is finished or if you are explicitly asked for it,
you have to create a clean commit series.

1. Save branch to "contrib-doc-pr.v1"
   ```
   $ cd s390-tools
   ~/s390-tools $ git branch contrib-doc-pr.v1
   ```

2. Use interactive git rebase to merge commits, adjust commit messages,
   and rebase onto your local master branch
   ```
   ~/s390-tools $ git rebase -i master
   ```

   An editor is started and shows the following:
   ```
   pick 2c73b9fc CONTRIBUTING: Outline steps to submit code
   pick fcfb0412 CONTRIBUTING: Add update PR info
   ```

   To merge the update into the original commit, replace "pick fcfb0412"
   with "squash fcfb0412".

   ```
   pick 2c73b9fc CONTRIBUTING: Outline steps to submit code
   squash fcfb0412 CONTRIBUTING: Add update PR info
   ```

   Save the document and exit the editor to finish the merge. Another editor
   window is presented to modify the commit message.

   You now could change the commit message as follows:

   ```
   CONTRIBUTING: Outline steps to submit code

   Explain in more detail how to submit s390-tools contributions as GitHub
   pull requests and how to update already submitted pull requests.

   Signed-off-by: Random Developer <random@developer.example.com>
   ```

   With interactive rebasing you can also change the order of commits and
   modify commit messages with "reword".

3. Use `git push` with the force option to replace the existing pull request
   with your locally modified commits
   ```
   ~/s390-tools $ git push --force origin contrib-doc-pr
   ```

### Rebase a pull request

If changes are made to the master branch in the official s390-tools
repository you may be asked to rebase your branch with your contribution
onto it. This can be required to prevent any merge conflicts that might
arise when integrating your contribution.

1. Fetch all upstream changes from the official s390-tools repository,
   rebase your local master branch and update the master branch
   on your fork
   ```
   ~/s390-tools $ git fetch upstream
   ~/s390-tools $ git checkout master
   ~/s390-tools $ git rebase upstream/master
   ~/s390-tools $ git push origin master
   ```

2. Rebase your branch with your contribution onto the master branch of
   the official s390-tools repository
   ```
   ~/s390-tools $ git checkout contrib-doc-pr
   ~/s390-tools $ git rebase master
   ```

3. Use `git push` with the force option to replace the existing pull
   request with your locally modified commits
   ```
   ~/s390-tools $ git push --force origin contrib-doc-pr
   ```
