# Worflows

## [Reusable detect changes workflow](_detect_changes.yml)

This sub workflow detects and enumerates the changes between two branches.

It is composed of five steps:

1. **Check out PR target branch** - This step checks out the latest commit of the PR target branch for the current repository. This workflow was designed to detect changes when a PR to a target branch was created. Therefore, the latest commit of the target branch must be checked out as the first step. To achieve this, GitHub's [**checkout**](https://github.com/actions/checkout) action is used with the following parameters:
   1. **ref** - The branch, tag or SHA to checkout - It is set to `github.base_ref`, which corresponds to the **PR target branch**.
2. **Check out source branch latest commit** - This step checks out the latest commit of the source branch on top of the previous one. To do so, GitHub's [**checkout**](https://github.com/actions/checkout) action is used with the following parameters:
   1. **clean** - Whether to execute `git clean -ffdx && git reset --hard HEAD` before fetching - It is set to false, which means **do not delete untracked files**.
3. **Generate summary** - This step creates the title for the action summary. As a matter of fact, the detected changes will be reported below the title in the summary section. The step is performed only if one or both *backend_directories* and *frontend_directories* inputs are not empty.
4. **Generate diffs for backend** - This step detects and enumerates the files that changed between the two branches. This is performed using [`git diff`](https://git-scm.com/docs/git-diff) command. Specifically, the code instructs git to show the changes in the *backend_directories* relative to `origin/<github.base_ref>` (the target branch). During this process, the [**pathspec**](https://git-scm.com/docs/gitglossary#Documentation/gitglossary.txt-aiddefpathspecapathspec) is used to exclude files or directories specified in the *backend_exclusions* input. The changes are then enumerated and output through the *backend* variable.
5. **Generate diffs for frontend** - This step follow the same pattern as the **Generate diffs for backend** step but for the frontend directories.

### Documentation

#### Inputs

* **backend_directories** - Optional - Space separated list of backend directories to check for changes. By default, it is set to an empty string.
* **backend_exclusions** - Optional - Space separated list of backend files or directories to **exclude** when checking for changes. Globs are supported. By default, it is set to an empty string.
* **frontend_directories** - Optional - Space separated list of frontend directories to check for changes. By default, it is set to an empty string
* **frontend_exclusions** - Optional - Space separated list of frontend files or directories to **exclude** when checking for changes. Globs are supported. By default, it is set to an empty string.
* **ubuntu_version** - Optional - The Ubuntu version to run the workflow against. By default, it is set to `latest`.

#### Outputs

* **backend** - The number of backend files that have changed.
* **frontend** - The number of frontend files that have changed.

## [Reusable node tests workflow](_node.yml)

This sub workflow install node dependencies and run frontend linters and tests.

It is composed of nine steps:

1. **Check out latest commit for current branch** - This step checks out the latest commit for the current branch of the repository. To do so, it uses GitHub's [**checkout**](https://github.com/actions/checkout) action with no parameters.
2. **Set up Node.js** - This step sets Node.js up downloading binaries and project's dependencies. This is done using the GitHub's [**setup-node**](https://github.com/actions/setup-node) action which also allows to cache and restore the project dependencies. It's used with the following parameters:
   1. **node-version** - Node.js version to use - It is set according to *node_version* input variable.
   2. **cache** - Which package manager used to install and cache packages - It is set to `npm`.
   3. **cache-dependency-path** - Path to the dependency file: `package-lock.json`, `yarn.lock` etc. It is set to `<working_directory>/package-lock.json`, where *working_directory* is the input variable.
3. **Add dependencies** - This step adds additional dependencies to the `package-lock.json` file. Specifically, these packages are added to the **devDependencies** part of the aforementioned file. Which packages will be added is chosen accordingly to input variables:
   1. *use_jest*
   2. *use_react*
   3. *use_eslint*
   4. *use_prettier*
   5. *use_stylelint*
4. **Install packages** - This step install all missing packages from the dependency file in the directory specified by the *working_directory* input variable.
5. **Run linters** - This step uses [**node_linter**](../actions/node_linter/action.yml) action to run linters against the frontend source code.
6. **Check packages licenses** - This step uses [**pilosus/action-pip-license-checker**](https://github.com/pilosus/action-pip-license-checker) to check the licenses used by the project requirements.
7. **Run CodeQL** - This step uses [**codeql**](../actions/codeql/action.yml) action to run CodeQL to discover vulnerabilities across the codebase.
8. **Run custom command** - This step is performed only if the input variable *custom_command* is not empty. The step simply run the bash command described in the previously mentioned input variable in the working directory specified by the *working_directory* input variable.
9. **Run jest tests** - This step runs Jest tests if the input variable *use_jest* is set to true. Finally, if *use_coverage* and *upload_coverage* are set to true, a coverage report is generated and uploaded.

### Documentation

#### Inputs

* **node_versions** - Required - An array of Node.js versions to use.
* **working_directory** - Required - Path to the `package.json` file
* **check_packages_licenses** - Optional - Whether to check npm packages licenses or not. By default it is set to true.
* **use_jest** - Optional - Whether to use Jest test suite or not. By default it is set to false.
* **use_react** - Optional - Whether react is used by the project or not. By default it is set to false.
* **use_eslint** - Optional - Whether to use ESlint linter or not. By default it is set to true
* **use_prettier** - Optional - Whether to use Prettier formatter or not. By default it is set to true.
* **use_stylelint** - Optional - Whether to use Stylelint linter or not. By default it is set to true.
* **use_coverage** - Optional - Whether to use Coverage or not. To work, it also require *use_jest* to be true. By default it is set to false.
* **upload_coverage** - Optional - Whether to upload coverage report to GitHub. By default it is set to false
* **run_codeql** - Optional - Whether to run CodeQL against the codebase. By default it is set to false.
* **custom_command** - Optional - A custom bash command to be run by the workflow. By default it is set to an empty string.
* **max_timeout** - Optional - A maximum amount of minutes allowed for the workflow to run. By default it is set to 30.
* **ubuntu_version** - Optional - The Ubuntu version to run the workflow against. By default it is set to `latest`.

## [Reusable python linter workflow](_python.yml)

This sub workflow runs Python linters and tests against the codebase.

It is composed of one job:

1. **python** - This job is composed of thirty-one steps:
   1. **Check out latest commit** - Checks out the latest commit on the current branch of the repository using the GitHub's [**checkout**](https://github.com/actions/checkout) action.
   2. **Set up Python** - Sets up Python on the runner machine using GitHub's [**setup-python**](https://github.com/actions/setup-python) action with the following parameter:
      1. **python-version** - Which Python version to use - It is set according to the *python_versions* input variable.
   3. **Inject stuff to environment** - This step adds a few environment variables to the system's environment. Specifically:
      1. If *django_settings_module* is set, **PYTHONPATH** and **DJANGO_SETTINGS_MODULE** will be added to the runner's environment.
      2. If *run_codeql* is true, **CODEQL_PYTHON** will be added to the runner's environment.
   4. **Restore APT cache related to PR event** - This step will try to restore the APT cache related to the PR event using [**restore_apt_cache**](../actions/apt_requirements/restore_apt_cache/README.md) with the following parameter:
      1. **apt_requirements_file_path** - Path to the APT requirements file - It is set to the *packages_path* input variable.
   5. **Restore APT cache related to target branch** - This step will try to restore the APT cache related related to the target branch (of the PR) using [**restore_apt_cache**](../actions/apt_requirements/restore_apt_cache/README.md) only if **Restore APT cache related to PR event** produces a cache miss. It is run with the following parameter:
      1. **apt_requirements_file_path** - Path to the APT requirements file - It is set to the *packages_path* input variable.
      2. **git_reference** - A git reference (name of the branch, reference to the PR) that will be used to build the cache key - It is set to the target branch.
   6. **Restore APT repositories** - If both PR event and target branch APT cache restore attempt resulted in a cache miss, the APT repositories list is refreshed using `sudo apt-get update`.
   7. **Install APT requirements** - This step installs APT requirements listed in the *packages_path* requirements file. **Since they are not required, recommended packages are not downloaded**.
   8. **Save APT cache related to PR event** - When the attempt to restore the APT cache related to the PR event results in a cache miss, the newly populated APT cache is saved to GitHub. This is performed using [**save_apt_cache**](../actions/apt_requirements/save_apt_cache/README.md) action with the following parameter:
      1. **apt_requirements_file_path** - Path to the APT requirements file - It is se to the *packages_path* input variable.
   9. **Create linter requirements file** - This step creates the linter requirements file using the [**create_linter_requirements_file**](../actions/python_requirements/create_linter_requirements_file/README.md) action.
   10. **Create dev requirements file** - This step creates the development requirements file using the [**create_dev_requirements_file**](../actions/python_requirements/create_dev_requirements_file/README.md) action.
   11. **Create docs requirement file** - This step creates the documentation requirements file using the [**create_docs_requirements_file**](../actions/python_requirements/create_docs_requirements_file/README.md) action.
   12. **Restore Python virtual environment related to PR event** - This step attempts to restore the Python virtual environment for the PR using the [**restore_python_virtualenv**](../actions/python_requirements/restore_virtualenv/README.md) action.
   13. **Restore Python virtual environment related to target branch** - If the attempt to restore the Python virtual environment for the PR, result in a cache miss, an attempt to restore the Python virtual environment for the target branch is made using the [**restore_python_virtualenv**](../actions/python_requirements/restore_virtualenv/README.md) action.
   14. **Create Python virtual environment** - If both attempts to restore the Python virtual environment for the PR, for the target branch, result in a cache miss, a Python virtual environment is created using the [**create_virtualenv**](../actions/python_requirements/create_virtualenv/README.md) action.
   15. **Restore pip cache related to PR event** - If both attempts to restore the Python virtual environment for the PR, for the target branch, result in a cache miss, an attempt to restore the pip cache for the PR event is made using the [**restore_pip_cache**](../actions/python_requirements/restore_pip_cache/README.md) action.
   16. **Restore pip cache related to target branch** - If both attempts to restore the Python virtual environment for the PR, for the target branch, as well as the pip cache for the PR, result in a cache miss, an attempt to restore the pip cache for the target branch is made using the [**restore_pip_cache**](../actions/python_requirements/restore_pip_cache/README.md) action.
   17. **Install project requirements** - If both attempts to restore the Python virtual environment for the PR event, and the target branch result in a cache miss, project requirements are installed from the working directory specified by the *install_from* input variable.
   18. **Install other requirements** - If the attempt to restore the Python virtual environment for the PR event result in a cache miss, developer, linters and documentation requirements are installed from the working directory specified by *working_directory* input variable.
   19. **Check requirements licenses** - If the input variable *check_requirements_licenses* is set to true and the attempt to restore the Python virtual environment related to the PR event result in a cache miss, this step performs the requirements licenses check using [**pilosus/action-pip-license-checker**](https://github.com/pilosus/action-pip-license-checker).
   20. **Print wrong licenses** - If the output of **Check requirements licenses** is `failure`, the list of licenses for which the check failed will be returned.
   21. **Save Python virtual environment related to PR event** - If the attempt to restore the Python virtual environment resulted in a cache miss, the Python virtual environment is saved for the PR event using the [*save_virtualenv*](../actions/python_requirements/save_virtualenv/README.md) action with the following parameter:
       1. **requirements_paths** - A space separated list of requirements file paths - It is set to the combination of *requirements_path*, `requirements-linters.txt`, `requirements-dev.txt` and `requirements-docs.txt` joined by spaces.
   22. **Save pip cache related to PR event** - If both attempts to restore the Python virtual environment and the pip cache related to the PR resulted in a cache miss, the pip cache is saved for the PR event using the [*save_pip_cache*](../actions/python_requirements/save_pip_cache/README.md) action.
   23. **Run linters** - If one of the following input variables: *use_black*, *use_isort*, *use_flake8*, *use_pylint*, *use_bandit* and *use_autoflake* is true, this step executes the linters against the codebase in the working directory specified by the *working_directory* variable.
   24. **Run CodeQL** - If the *run_codeql* input variable is true, this step runs CodeQL against the codebase using the [**codeql**](../actions/codeql/action.yml) action in the working directory specified by the *working_directory* variable.
   25. **Build Docs** - If the *check_docs_directory* input variable is set, this step executes `rstcheck` to ensure that the documentation in *check_docs_directory* is valid. Finally, the documentation is built using `sphinx`.
   26. **Start services** - If one or more of the following input variables: *use_postgres*, *use_elastic_search*, *use_memcached*, *use_redis*, *use_rabbitmq* and *use_mongo* are true, this step creates the Docker container for the service using the [**services**](../actions/services/action.yml) action. Additional parameters, such as *postgres_db* or *elasticsearch_version* can also be provided to the aforementioned action.
   27. **Start celery worker** - If the *use_celery* input variable is true, a Celery worker is created for the *celery_app* application. The `celery` command is executed in the working directory specified by the *working_directory* input variable.
   28. **Run custom command** - If the *custom_command* input variable is not empty, the command defined by the variable is executed in the working directory specified by the *working_directory* input variable.
   29. **Check migrations** - If *check_migrations* is true and *django_settings_module* is not empty, this step will perform a dry run of `django-admin makemigrations` to ensure that the migrations are valid.
   30. **Run unittest** - This step runs Python tests against the codebase in the directory described by the *working_directory* input variable. Additionally, according to *tags_for_manual_tests* and *tags_for_slow_tests* variables, some tests will be excluded from the run.
   31. **Create coverage output** - If *use_coverage* and *upload_coverage* are set to true, this step produces a coverage report of the codebase and uploads it to GitHub. The *working_directory* input variable is used to determines the directory in which coverage should be run.

### Documentation

#### Inputs

* **python_versions** - Required - Python versions used by this workflow in the form of a JSON array.
* **ubuntu_version** - Optional - Ubuntu version to run workflow against. By default, it is set to `latest`.
* **working_directory** - Required - Directory in which to run linters.
* **requirements_path** - Required - Path to the requirements file of the Python project.
* **install_from** - Optional - Directory where all installation commands will be run. By default, it is set to `.`.
* **packages_path** - Optional - Path to the APT requirements file of the Python project. By default, it is set to an empty string.
* **env** - Optional - A JSON object containing a set of environment variables to be added to the system's environment. By default, it is set to an empty JSON object `{}`.
* **max_timeout** - Optional - Maximum amount of time (in minutes) the workflow is allowed to run. By default, it is set to `30`.
* **use_black** - Optional - Whether to use black formatter. By default, it is set to `false`.
* **use_isort** - Optional - Whether to use isort formatter. By default, it is set to `false`.
* **use_ruff_formatter** - Optional - Whether to use ruff formatter. By default, it is set to `false`.
* **use_autoflake** - Optional - Whether to use autoflake linter. By default, it is set to `false`.
* **use_bandit** - Optional - Whether to use bandit linter. By default, it is set to `false`.
* **use_flake8** - Optional - Whether to use flake8 linter. By default, it is set to `false`.
* **use_pylint** - Optional - Whether to use pylint linter. By default, it is set to `false`.
* **use_ruff_linter** - Optional - Whether to use ruff linter. By default, it is set to `false`.
* **use_coverage** - Optional - Whether to use coverage. By default, it is set to `false`.
* **coverage_config_path** - Optional - Path to the coverage configuration file. By default, it is set to `.coveragerc`.
* **upload_coverage** - Optional - Whether to upload coverage report to GitHub. To work, it needs *use_coverage* to be true. By default, it is set to `false`.
* **run_codeql** - Optional - Whether to run CodeQL against codebase. By default, it is set to `false`.
* **use_celery** - Optional - Whether to create a Celery container. By default, it is set to `false`.
* **use_elastic_search** - Optional - Whether to create an Elasticsearch container. By default, it is set to `false`.
* **use_memcached** - Optional - Whether to create a Memcached container. By default, it is set to `false`.
* **use_mongo** - Optional - Whether to create a MongoDB container. By default, it is set to `false`.
* **use_postgres** - Optional - Whether to create a PostgresDB container. By default, it is set to `false`.
* **use_rabbitmq** - Optional - Whether to create a RabbitMQ container. By default, it is set to `false`.
* **use_redis** - Optional - Whether to create a Redis container. By default, it is set to `false`.
* **celery_app** - Optional - A Celery application name. Requires *use_celery* to be true. By default, it is set to an empty string.
* **celery_queues** - Optional - A comma separated list of Celery queues. Requires *use_celery* to be true. By default, it is set to `default`.
* **elasticsearch_version** - Optional - Elasticsearch's container version. By default, it is set to `latest`.
* **elasticsearch_port** - Optional - Elasticsearch's container exposed port. By default, it is set to `9200`.
* **memcached_version** - Optional - Mecached's container version. By default, it is set to `latest`.
* **mongo_version** - Optional - MongoDB's container version. By default, it is set to `latest`.
* **postgres_db** - Optional - PostgresDB database name. Requires *use_postgres* to be true. By default, it is set to `db`.
* **postgres_user** - Optional - PostgresDB user name. Requires *use_postgres* to be true. By default, it is set to `user`.
* **postgres_password** - Optional - PostgresDB password. Requires *use_postgres* to be true. By default, it is set to `password`.
* **postgres_version** - Optional - PostgresDB's container version. Requires *use_postgres* to be true. By default, it is set to `latest`.
* **rabbitmq_version** - Optional - RabbitMQ's container version. Requires *use_rabbitmq* to be true. By default, it is set to `latest`.
* **redis_version** - Optional - Redis' container version. Requires *use_redis* to be true. By default, it is set to `latest`.
* **django_settings_module** - Optional - Path to the Django settings file. By default, it is set to an empty string.
* **check_migrations** - Optional - Whether to check that the project's migrations are valid. Requires *django_settings_module* to be set. By default, it is set to `false`.
* **check_requirements_licenses** - Optional - Whether to check that the requirements license is valid. Requires *django_settings_module* to be set. By default, it is set to `true`.
* **ignore_requirements_licenses_regex** - Optional - A regex that describes which directories should be ignored when checking the validity of requirements licenses. By default, it is set to `uWSGI.*|lunardate.*|.*QuokkaClient.*|pyquokka.*`.
* **tags_for_slow_tests** - Optional - A space separated list of tags for tests that will only be run on the master/main branch. **Works only for Django projects**. By default, it is set to an `slow`.
* **tags_for_manual_tests** - Optional - A space separated list of tags for tests that will only be run **manually** (CI will ignore them). **Works only for Django projects**. By default, it is set to `manual`.
* **custom_command** - Optional - A custom bash command to run. By default, it is set to an empty string.
* **check_docs_directory** - Optional - Path to the documentation directory in which `rstcheck` will be run to check documentation files. By default, it is set to an empty string.
* **check_dockerfile** - Optional - Path to a Dockerfile to be checked. **Warning: if set it may significantly increase the action time**. By default, it is set to an empty string.

## [Create APT cache](create_apt_cache.yaml)

This workflow is run in the event of **a push on branches *main*, *master*, *develop*, *dev***. Specifically, it is triggered only when the APT requirements file is updated.

The workflow is composed of a single job:

1. **Create cache for APT dependencies** - This job, as described by its name, creates a cache for APT dependencies and stores it on GitHub. It is composed of four steps:
   1. **Check out latest commit on current branch** - This step checks out the latest commit on the current branch of the repository.
   2. **Install APT dependencies** - This step refreshes APT repositories and then install the project dependecies. This action is required to produce the APT cache that will be saved later.
   3. **Save APT cache** - This step saves APT cache on GitHub. The GitHub's [**save_apt_cache**](../actions/apt_requirements/save_apt_cache/README.md) action is used.

## [Create Python cache](create_python_cache.yaml)

This workflow is run in the event of **a push on branches *main*, *master*, *develop*, *dev***. Specifically, it is triggered only when the Python requirements file is updated.

The workflow is composed of a single job:

1. **Create cache for Python dependencies** - This job, as described by its name, creates a cache for Python dependencies and stores it on GitHub. It is composed of four steps:
   1. **Check out latest commit** - This step checks out the latest commit on the current branch for the repository.
   2. **Install system dependencies required by Python Packages** - **OPTIONAL** - Sometimes, Python packages require one or more system dependencies. For instance, `python-ldap` Python package requires `libldap2-dev` and `libsasl2-dev`, System dependencies, for a successful installation. This step allows user to install system dependencies required by Python packages.
   3. **Set up Python** - This step install Python on the runner.
   4. **Set up Python virtual environment** - This step uses [**create_virtualenv**](../actions/python_requirements/create_virtualenv/README.md) action to create a Python virtual environment.
   5. **Install Python dependencies** - This step install Python requirements to produce the final virtual environment that will be cached. Also, installing the Python dependencies, creates the pip cache.
   6. **Save pip cache** - This step uses [**save_pip_cache**](../actions/python_requirements/save_pip_cache/README.md) action to save pip's download cache on GitHub.
   7. **Create virtual environment cache** - This step uses [**save_virtualenv**](../actions/python_requirements/save_virtualenv/README.md) action to save virtual environment on GitHub's cache.

## [CI](pull_request_automation.yml)

This workflow runs in the case of a **pull request on branches *master*, *main*, *develop*, *dev*** and it's the core CI workflow.

It is composed of three jobs:

1. **detect-changes** - This job detects and enumerates changes to backend and/or frontend files. To do so, it uses the [**_detect_changes**](_detect_changes.yml) workflow.
2. **node** - If any changes to the frontend files are found, [**_node**](_node.yml) workflow is run.
3. **python** - If any changes to the backend files are found, [**_python**](_python.yml) workflow is run.

## [Release and publish](release.yml)

TODO

## [Reusable release and tag workflow](_release_and_tag.yml)

TODO

## [Build and publish Docker images](docker_publish.yml)

This workflow builds the `greedybear` and `greedybear_nginx` images and publishes them to the **GitHub Container Registry (GHCR)** under `ghcr.io/greedybear-project`, decoupling image hosting from the IntelOwl-owned DockerHub account.

It runs on:

* pushes to **main** — tagged `prod`
* pushes to **develop** — tagged `stag`
* pushes of a **`X.Y.Z` git tag** — tagged with that version

Each image is built via a job matrix and pushed by [**docker/build-push-action**](https://github.com/docker/build-push-action), with tags/labels derived by [**docker/metadata-action**](https://github.com/docker/metadata-action) and layer caching backed by the GitHub Actions cache.
