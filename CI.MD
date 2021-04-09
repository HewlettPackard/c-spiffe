# Continuous Integration (CI)

Our Continuous Integration pipeline currently runs on Github Actions and is executed on push. As mentioned in [BUILDING.md](BUILDING.md), the whole process runs on a container. The following steps are run in order:

* The project is checked out
* Create a build environment and configure cmake
* Build the project
* Run unit tests
* Generate coverage reports
* Run integration tests
* Upload coverage to code cov
* Verify if current coverage is acceptable for lines and functions
  
If any of the above steps fail, the build fails. Any Pull Request with failing builds should be rejected.

