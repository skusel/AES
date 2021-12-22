# Contributing
Thank you for your interest in this project!

## Feature Requests and Reporting Bugs
If you would like to request a feature or if you see a bug in the code and want to report it, please open an [issue](https://github.com/skusel/AES/issues/new).

## Contributing a Feature or Patch
If you would like to contribute to the code, please create a [pull request](https://github.com/skusel/AES/pulls). Pull requests will not be pulled in unless all GitHub workflows pass.

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

## Compiler Support
This code has been built with AppleClang 13.0.0.13000029 on macOS and with GCC 9.3.0 on Ubuntu. No guarentees can be made about its ability to be built on other compilers, but it is intended to work on any compiler that supports the C++17 standard.

## Style
In general, you should follow the style of the code around you. Below are a few style points I would like to highlight.
- Indentation should be 2 **spaces**, not tabs.
- Brackets should only be used when absolutely necessary or if they make the code clearer. They should always be placed on the next line.
- Class names should follow UpperCammelCase format.
- Functions and variables should follow lowerCammelCase format.
- Class member variables should being with `m_`.
- Keep functions small, readable, and easily testable.

