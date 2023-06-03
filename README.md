# obfuscated-tor-bridge
Bash script to setup an obfuscated Tor bridge

### Summary
  * Setup and configure Linux with minor changes, including monthly traffic limit
  * Setup automatic updates
  * Install and auto configure Tor to run as an Obfs4proxy Bridge
  
## Customize these Variables
   * VERSION (Script tested with Debian 11 (Buster)
   * PREFIX (combined with hostname). Used to identify the status of your bridge. Might have to use the hashed fingerprint instead.
     * see: https://atlas.torproject.org
   * ALLOWUSERS: Restrict SSH access per user and/or IP address
   * SSH_PUB_KEY: Add your pub key here
   * SSH_PORT: Alternative SSH Port
   * Note: Check the syntax using `bash -n`

### Examples
     * LINUX_VERSION=bullseye
     * PREFIX=00000
     * ALLOWUSERS="AllowUsers root@1.1.1.1"
     * ALLOWUSERS="AllowUsers root@X.X.0.0/16" #Or from a specific network
     * SSH_PUB_KEY="ssh-ed25519 ..."
     * SSH_PORT=922
