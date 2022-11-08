<!-- PROJECT LOGO -->
<p align="center">
  <h3 align="center">php-probe</h3>

  <p align="center">
    PHP runtime application self-protection.
    <br />
    <br />
    <a href="https://github.com/bytedance/Elkeid/issues">Report Bug</a>
    ·
    <a href="https://github.com/bytedance/Elkeid/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgements">Acknowledgements</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

Hook `functions` and `opcodes` of PHP, transfer api call arguments/stacktrace by unix socket, support PHP 5.3 and above.

### Built With

* [GCC](https://gcc.gnu.org)
* [Make](https://www.gnu.org/software/make)
* [CMake](https://cmake.org)



<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

* CMake
  ```sh
  curl https://github.com/Kitware/CMake/releases/download/v3.21.0/cmake-3.21.0-linux-x86_64.sh | sh
  ```

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/bytedance/Elkeid.git
   ```
2. Update submodule
   ```sh
   git submodule update --init --recursive
   ```
3. Build with `php-config`
   ```sh
   mkdir -p build && cmake -B build -DCMAKE_MODULE_PATH=$(pwd)/cmake && cmake --build build -j$(nproc)
   ```
4. Build with include path
   ```sh
   mkdir -p build && cmake -B build -DPHP_EXTENSIONS_INCLUDE_DIR=/path/php/include && cmake --build build -j$(nproc)
   ```



<!-- USAGE EXAMPLES -->
## Usage

Start server:
```sh
# each message is be composed of a 4-byte length header, and a json string.
socat UNIX-LISTEN:"/var/run/smith_agent.sock" -
```

Start PHP:
```sh
php -d 'extension=$(pwd)/lib/libphp_probe.so' -r "shell_exec('ls'); sleep(60);"
```



<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/bytedance/Elkeid/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the Apache-2.0 License.



<!-- CONTACT -->
## Contact

Bytedance - [@bytedance](https://github.com/bytedance)

Project Link: [https://github.com/bytedance/Elkeid](https://github.com/bytedance/Elkeid)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [libevent](https://github.com/libevent/libevent)
* [json](https://github.com/nlohmann/json)