# obfuscated-tor-bridge
Quick script to setup an obfuscated tor bridge

####Summary
  * Installs & Configures an obfuscated Tor Bridge
  * Sets up automatic updates
  * Misc Config settings for a VPS provider
  
  ####Variables
   * VERSION (Script works for Debian Jessie & Wheezy)
   * PREFIX (used to identify the status of your bridges using atlas)
     * see: https://atlas.torproject.org
   * ALLOWUSERS: variable for restricting SSH access to a user and/or an IP address
   * SSH_PUB_KEY: Add your pub key here
    * Note: You can always check the syntax of a bash script using `bash -n`


  ####Examples
 <code>
     * VERSION=jessie
     * PREFIX=0000
     * ALLOWUSERS="AllowUsers root@*.*.*.*"
     * SSH_PUB_KEY="ssh-rsa ..."</code>

