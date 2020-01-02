<!--- Copyright (C) Lightbend Inc. <https://www.lightbend.com> -->
# Play contributor guidelines

The canonical version of this document can be found on the [Play contributor guidelines](https://playframework.com/contributing) page of the Play website.

## Prerequisites

Before making a contribution, it is important to make sure that the change you wish to make and the approach you wish to take will likely be accepted, otherwise you may end up doing a lot of work for nothing.  If the change is only small, for example, if it's a documentation change or a simple bugfix, then it's likely to be accepted with no prior discussion.  However, new features, or bigger refactorings should first be discussed on the [our forums](https://discuss.lightbend.com/c/play).  Additionally, there are issues labels you can use to navigate issues that a good start to contribute:

- [`help wanted`](https://github.com/playframework/playframework/labels/help%20wanted)
- [`type:community`](https://github.com/playframework/playframework/labels/type%3Acommunity)
- [`good first issue`](https://github.com/playframework/playframework/labels/good%20first%20issue)

### Procedure

1. Make sure you have signed the [Lightbend CLA](https://www.lightbend.com/contribute/cla); if not, sign it online.
2. Ensure that your contribution meets the following guidelines:
    1. Live up to the current code standard:
        - Not violate [DRY](https://www.oreilly.com/library/view/97-things-every/9780596809515/ch30.html).
        - [Boy Scout Rule](https://www.oreilly.com/library/view/97-things-every/9780596809515/ch08.html) needs to have been applied.
    2. Regardless of whether the code introduces new features or fixes bugs or regressions, it must have comprehensive tests.  This includes when modifying existing code that isn't tested.
    3. The code must be well documented in the Play standard documentation format (see the [documentation guidelines](https://playframework.com/documentation/latest/Documentation).)  Each API change must have the corresponding documentation change.
    4. Implementation-wise, the following things should be avoided as much as possible:
        - Global state
        - Public mutable state
        - Implicit conversions
        - ThreadLocal
        - Locks
        - Casting
        - Introducing new, heavy external dependencies
    5. The Play API design rules are the following:
        - Play is a Java and Scala framework, make sure any changes have feature parity in both the Scala and Java APIs.
        - Java APIs should go to `core/play/src/main/java`, package structure is `play.myapipackage.xxxx`
        - Scala APIs should go to `core/play/src/main/scala`, where the package structure is `play.api.myapipackage`
        - Features are forever, always think about whether a new feature really belongs to the core framework or if it should be implemented as a module
        - Code must conform to standard style guidelines and pass all tests (see [Run tests](https://www.playframework.com/documentation/latest/BuildingFromSource#run-tests))
    6. Basic local validation:
        - Not use `@author` tags since it does not encourage [Collective Code Ownership](https://www.extremeprogramming.org/rules/collective.html).
        - Run `scripts/local-pr-validation.sh` to ensure all files are formatted and have the copyright header.
3. Ensure that your commits are squashed.  See [working with git](https://playframework.com/documentation/latest/WorkingWithGit) for more information.
4. Submit a pull request.

If the pull request does not meet the above requirements then the code should **not** be merged into master, or even reviewed - regardless of how good or important it is. No exceptions.

The pull request will be reviewed according to the [implementation decision process](https://playframework.com/community-process#Implementation-decisions).
