# SOC / SIEM Apps / ELK

`soc_siemapp_elk`'s alerting is an Elasticsearch alerting tool.
It runs standardized searches (*usecases*) against an Elasticsearch cluster then index and forward the results (*alerts*).

## Installation
It is **highly recommended** to install the tool within a virtual environment.

### Dependencies
* `python3`: Python interpreter in version 3.4+
* `pip`: Python package manager

### Virtual environment
* Install `virtualenv` on the target system if needed: `pip3 install virtualenv`
* Create a virtual environment: `python3 -m virtualenv <path/to/your/venv>`
* Activate the virtual environment: `source <path/to/your/venv>/bin/activate`

### Install the package
If you wish to keep the package up-to-date with the GIT repository:
* Clone the repository: run `git clone https://scm.tld/soc_siemapp_elk.git`
* Install the package: run `pip3 install -e soc_siemapp_elk`

Otherwise:
* Install the package: run `pip3 install <path/to/package>`

## Usage
The tools provides several CLI commands:

### CLI usage
Syntax:
```
soc_siemapp_elk [-h]
                --config <path/to/config.json>
                --logfile <path/to/logfile>
                 <command> [command arguments]
```

Arguments:
* `-h`: Show help.
* `--config`: Path to the tool configuration file (optional).
* `--logfile`: Path to log file (optional).


### `list` command
This command list the requested `object` instances.

Syntax:
```
... list <object>
```

Arguments:
* `<object>`: Select the object type to list.
  `usecases` is currently the only available object type.


### `find` command
This command find the alerts raised and indexed by the given use case.

Syntax:
```
... find <usecase name>
```

Arguments:
* `<usecase name>`: Name of the use case to search for.



### `run` command
This command executes the requested `usecase` against Elasticsearch.

Syntax:
```
... run [--noindex]
        [--nofilter]
        [--dump]
        <usecase name>
```

Arguments:
* `--noindex`: Do not write-back the use case alerts to Elasticsearch.
* `--nofilter`: Do not apply the use cases thresholds.
* `--dump`: Output the use case result.
