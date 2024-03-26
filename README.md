# System Capabilities Reporter

Sysreport is a system capability reporting tool that gives application developers a quick summary of what performance features are available on the Linux system the tool is running on.

This tool is aimed at anyone trying to profile performance on Arm-based systems; this includes cloud instances, bare metal servers, and small devices such as developer boards and Raspberry Pi devices.

The tool is invoked on the command-line and takes about a second to run. It displays a single page of output in text format.

Sysreport is not a benchmarking tool and does not modify the system in any way.

This tool aims to:
* Report system configuration in a way that is focused on performance analysis, list which performance tools and features are available
* Give useful advice on what you might do to improve your configuration for performance analysis
* Run on any system (bare metal vs VM vs container, different operating systems and kernels, root vs non-root access, etc.)
* Save the user from having to read multiple pages of documentation to understand what individual commands to run to gather everything they need

Example use cases:
* As a developer, I want to know if my cloud instance supports a particular performance feature I require, so that I am able to debug a performance problem
* As a developer, I want a quick single page summary of my system's performance configuration, so that I don't have to run lots of different commands manually
* As a developer, I would like to know suggested configuration changes I can make to my system, so that I can improve my ability to collect performance information

## Usage

Clone this git repository (or copy the repository contents) onto the target system for evaluation:
```sh
git clone https://github.com/ArmDeveloperEcosystem/sysreport.git
```

Now change into the `src` directory:
```sh
cd sysreport/src
```

To print usage help:
```sh
python sysreport.py --help
```

Example usage:
* System overview with increased verbosity:
  ```sh
  python sysreport.py --verbose
  ```
* Check which kernel configuration options were set at build time:
  ```sh
  python sysreport.py --config
  ```
* System overview with additional information about which security vulnerabilities the system is exposed to:
  ```sh
  python sysreport.py --vulnerabilities
  ```

## Learning Path

Check out the [Arm Learning Path](https://learn.arm.com/learning-paths/servers-and-cloud-computing/sysreport) for this tool.

## Compatibility

This tool only supports Linux. It has been tested on a variety of Arm-based systems in different configurations.

Please consider raising an issue in GitHub if this tool does not work as expected on your system.

## License

[Apache-2.0 License](LICENSE)

## Acknowledgements

This project was created on behalf of the [Arm Software Developers](https://developer.arm.com/) team, follow them on Twitter: [@ArmSoftwareDev](https://twitter.com/armsoftwaredev) and YouTube: [Arm Software Developers](https://www.youtube.com/channel/UCHUAckhCfRom2EHDGxwhfOg) for more resources!
