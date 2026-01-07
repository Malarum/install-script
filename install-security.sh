#!/bin/bash

help_menu() {
    echo 'This script is made to install check-mk, huntress, and Wazuh at once'
    echo 'Usage:'
    echo '-h or --help: print this help menu'
    echo '-v or --version: print he script version'
    echo '-a or --all: install all 3 products'
    echo '-H or --huntress: install huntress'
    echo '-c or --checkmk: install checkmk'
    echo '-w or --wazuh: install wazuh'
}


function install_huntress() {
    if [ -d "/usr/share/huntress" ]; then
        echo "[+] Huntress Agent already installed skipping..."
        return 0
    fi

    if [ ! -f "/tmp/huntress-linux-install.sh" ]; then
        echo "[+] Downloading Huntress..."
        wget "https://huntresscdn.com/huntress-installers/linux/huntress-linux-install.sh" -P /tmp > /dev/null 2>&1
    fi
        if [ -f "/tmp/huntress-linux-install.sh" ]; then
            echo "[+] Huntress successfully downloaded installing..."
            chmod +x /tmp/huntress-linux-install.sh
	    read -p "Enter you Huntress account key: " acckey
	    read -p "Enter you Huntress organization key: " orgkey
            /tmp/huntress-linux-install.sh -a "$acckey" -o "orgkey"
            sleep 5
            if [ "$(pgrep -x "huntress-agent")" ]; then
                echo "[+] Huntress installed and running" 
            fi
            if ! crontab -l >/dev/null 2>&1; then
                echo "[+] No crontab found...creating crontab"
                echo '0 0 * * * /usr/bin/systemctl restart huntress-rio.service' > /tmp/cron
                crontab /tmp/cron
                echo "[+] cronjob successfully added"
                rm /tmp/cron
            else
                echo '[+] crontab found for root. Adding to crontab'
                crontab -l > /tmp/cron
                echo "0 0 * * * $(which systemctl) restart huntress-rio.service" >> /tmp/cron
                crontab /tmp/cron
                rm /tmp/cron
                echo '[+] cronjob added'
            fi

        fi
    echo "[+] Cleaning up artifacts..."
    rm /tmp/huntress-linux-install.sh

}

function install_checkmk() {

    choice=""
    until [[ "$choice" == "Y" || "$choice" == "N" || "$choice" == "y" || "$choice" == "n" ]]; do
        read -p "CheckMK Installer. Have you added the host to checkmk? [Y/N]: " choice
        if [[ "$choice" == "N" || "$choice" ==  "n" ]]; then
            echo '[+] Exiting CheckMK installer module. Please setup the host in CheckMK first and then rerun this script with ./install-security -c or --checkmk'
            return 1
        elif [[ "$choice" == "Y" || "$choice" == "y" ]]; then
            if [ -f "/usr/bin/cmk-agent-ctl" ]; then
                    echo "[+] CheckMK agent already installed skipping..."
                    return 0
            fi
        else
            echo "Invalid choice. Please Enter Y/N"
        fi
    done

    echo "[+] Checking that the CheckMK server can be contacted"
    if [ "$(ping -c 4 10.20.240.202)" &> /dev/null ]; then
        echo "[+] Successfully contacted the CheckMK server continuing..."
    
    else
        echo "[+] Unable to contact CheckMK server. Please make sure this device can contact it at check.company.com"
        return 1
    fi

    if [ ! -f "/tmp/check-mk-agent_2.3.0p26-1_all.deb" ]; then
            echo "[+] Downloading CheckMK Agent..."
            wget "https://check.company.com/monitoring/check_mk/agents/check-mk-agent_2.3.0p26-1_all.deb" -P /tmp > /dev/null 2>&1
    fi

    if [ -f "/tmp/check-mk-agent_2.3.0p26-1_all.deb" ]; then
            echo "[+] CheckMK agent downloaded, installing"
            apt install /tmp/check-mk-agent_2.3.0p26-1_all.deb > /dev/null 2>&1
            sleep 5
            echo "[+] Registering agent...make sure you have the password for the your user"
            sleep 5
            cmk-agent-ctl register --server check.company.com --site monitoring --user user --hostname $(hostname)
            echo '[+] Agent registered please remember to open tcp port 6556'
    else
            echo "[+] Failed to download agent..."
            return 1        
    fi

    echo "[+]Cleaning up artifacts..."
    rm /tmp/check-mk-agent_2.3.0p26-1_all.deb

}

function install_wazuh() {
    if [ -d "/var/ossec" ]; then
        echo '[+] Wazuh already installed skipping...'
        return 0
    fi

    echo "[+] Checking that the Wazuh server can be contacted"
    if [ "$(ping -c 4 10.20.240.202)" &> /dev/null ]; then
        echo "[+] Successfully contacted the Wazuh server continuing..."
    
    else
        echo "[+] Unable to contact Wazuh server. Please make sure this device can contact it at 10.20.240.202"
        return 1
    fi

    if [ ! -f "/tmp/wazuh-agent_4.13.1-1_amd64.deb" ]; then
        echo "[+] Downloading Wazuh agent..."
        wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.1-1_amd64.deb -P /tmp >/dev/null 2>&1
    fi
    if [ -f "/tmp/wazuh-agent_4.14.1-1_amd64.deb" ]; then
        WAZUH_MANAGER='10.20.240.202' WAZUH_AGENT_NAME="$(hostname)" dpkg -i /tmp/wazuh-agent_4.14.1-1_amd64.deb >/dev/null 2>&1
    fi

    echo "[+] Cleaning up artifacts..."
    rm /tmp/wazuh-agent_4.14.1-1_amd64.deb
    echo "[+] Starting and Enabling Wazuh Service..."
    systemctl start wazuh-agent.service && systemctl start wazuh-agent.service
    sleep 5
    if [ "$(pgrep -f "wazuh-agent")" ]; then
        echo "[+] Agent started successfully"
        return 0
    else
        echo "[+] Agent failed to start please run sudo systemctl start wazuh-agent to see what went wrong..."
        return 1    
    fi


}

function main() {
    user="$(whoami)"
        if [ "$(id -u $user)" != 0 ]; then
            echo "Please run this script as root"
            exit 0
        fi    

    all=false
    huntress=false
    wazuh=false
    checkmk=false

    if [ -z "$1" ]; then
        help_menu

    else
        for arg in $@; do
            case "$arg" in 
                "-v"|"--version")
                    echo "Installer script version 0.1"
                    ;;

                "-h"|"--help")
                    help_menu
                    ;;
                "-a"|"--all")
                    all=true
                    ;;
                "-H"|"--huntress")
                    huntress=true
                    ;;
                "-w"|"--wazuh")
                    wazuh=true
                    ;;
                "-c"|"--checkmk")
                    checkmk=true
                    ;;
               
                esac
            done
            if $all && ($huntress || $wazuh || $checkmk); then
                echo "You cannot use all with these arguments"
                exit 1
            fi
            if $all; then
                install_huntress
                install_checkmk
                install_wazuh
            else
                $huntress && install_huntress
                $checkmk && install_checkmk
                $wazuh && install_wazuh
            fi   
    fi

}

main "$@"

