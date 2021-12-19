# AES
Implementation of the AES algorithm.

## Building and Testing
This section assumes you will run the following commands from the root of the repository.

This project comes with CMake presets to configure the build system, build the code, and run tests.

To generate debug build files:
```
cmake --preset=debug
```

To generate release build files:
```
cmake --preset=release
```

To create a debug build:
```
camke --build --preset=debug-build
```

To create a release build:
```
cmake --build --preset=release-build
```

To run tests:
```
ctest --preset=debug-test
```

To run tests with verbose output:
```
ctest --preset=debug-test -V
```

To run tests whose name matches a specific regex:
```
ctest --preset=debug-test --tests-regex <some regex you want to match>
```
