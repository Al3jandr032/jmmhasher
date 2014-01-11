# JMMHASHER

This library project aims to replace the default hasher included in the
[Japanese Media Manager][1] application. It also aims to be compiled cross-
platform as well as be usable with Python.

In order to meet these goals, jmmhasher will be written in plain C for the core
library and contain specific interface files when compiling for each platform.
This will allow the hasher to run as fast as possible while minimizing the
complexity of the application by separating the shared core from the platform
specific needs of each compile target.

## License

In spirit of the original program and in spirit of open source, this library
will be licensed under the Lesser GNU Public License v3 included in the sister
file [LICENSE.txt][2].

  [1]: http://code.google.com/p/jmm "Japanese Media Manager"
  [2]: LICENSE.txt "GPLv3 and LGPLv3 license"
