# Info Gathering Tool

This is a basic information gathering tool designed to retrieve domain-related details, perform DNS queries, geolocation, and utilize services like Shodan and Censys.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/dedlinux777/Info_gathering.git
    ```

2. Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

To use this tool, run the `info_gathering.py` script with appropriate arguments:

```bash
python3 info_gathering.py -d DOMAIN [-s IP] [-i DOMAIN_NAME] [-n IP_ADDRESS] [-o OUTPUT_FILE]


Replace DOMAIN, IP, DOMAIN_NAME, IP_ADDRESS, and OUTPUT_FILE with your desired inputs.

Options
-d, --domain: Enter a domain to gather information.
-s, --ip_search: Enter an IP address for Shodan and Censys search.
-i, --get_host_ip: Enter a domain name only to get the host's IP.
-n, --get_host_name: Enter an IP address only to get the host's name.
-o, --output: Enter a file for saving the output.

License
This project is licensed under the MIT License.


Replace `your-username` with your actual GitHub username and modify the instructions and descriptions as needed to suit your project. This README provides a basic structure covering installation, usage, and licensing information. Feel free to expand or customize it further according to your project's requirements and additional details you want to include.