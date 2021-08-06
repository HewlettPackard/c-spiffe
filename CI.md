<!--
(C) Copyright 2020-2021 Hewlett Packard Enterprise Development LP

 

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

 

    http://www.apache.org/licenses/LICENSE-2.0

 

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

-->


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
