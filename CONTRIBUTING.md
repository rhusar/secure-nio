# Contributing to Secure NIO

Contributions are welcome – bug reports, documentation fixes, tests, and code alike.

## Just Say Hi

No need to write code to contribute.
If you hit the problem this library exists for – the JDK ships `SocketChannel` and `DatagramChannel`, but no secured implementation of either, so wiring up `SSLEngine` by hand is left as an exercise to the reader –
and you went looking for something like this, just say hi on
[GitHub](https://github.com/rhusar/secure-nio/issues).
That applies whether you ended up using the library, read through the sources, or merely skimmed the README and moved on.

Knowing that someone else ran into the same problem is entertaining, and so is hearing:

* what you were trying to build, and how you solved it in the end if not with this,
* what was confusing, missing, or surprising,
* and what did not work – even if you did not get far enough to file a proper bug report.

Half-formed feedback and questions are welcome.
There is no such thing as too small a note.

## Reporting Issues

Please report bugs and feature requests via [GitHub Issues](https://github.com/rhusar/secure-nio/issues).
For a bug, include the JDK version and operating system, and – where possible – a minimal reproducer.

Do **not** report security vulnerabilities through public issues.
Instead, use [GitHub's private vulnerability reporting](https://github.com/rhusar/secure-nio/security/advisories/new).

## Building

```sh
mvn clean verify
```

Requires JDK 17 or higher and Maven (or use the bundled `./mvnw` wrapper).
The build generates a self-signed test keystore automatically, so no manual setup is required.

## Pull Requests

* Fork the repository and work on a topic branch.
* Keep each pull request focused on a single change.
* Add or update tests covering the change; the loopback test cases under
  `impl/src/test/java/io/github/rhusar/securenio/channels/` are good starting points.
* Ensure `mvn clean verify` passes before opening the pull request.
* CI builds every pull request on Linux, macOS, and Windows across all supported JDKs; all checks must pass before merging.

## Coding Style

* Match the style of the surrounding code – the project targets Java 17 and has no runtime dependencies; please do not introduce any.
* Formatting is enforced by [EditorConfig](.editorconfig) and checked in CI: UTF-8, LF line endings, four-space indentation, and a trailing newline.
* Every source file carries the Apache 2.0 license header; run `mvn license:format` to add it to new files.
* Public API additions need Javadoc.

## Commit Messages

Write a descriptive imperative summary line.

## Developer Certificate of Origin

All contributions must be signed off under the [Developer Certificate of Origin](dco.txt).
Sign off by adding a `Signed-off-by` line to each commit, which `git commit -s` does for you:

```sh
git commit -s -S -m "Fix handshake retransmission on packet loss when running on Plumbus"
```

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
