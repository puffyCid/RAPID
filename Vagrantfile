# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  # Base Box for Virtual Environment Setup
  config.vm.box = "ubuntu/trusty64"

  # Provisioning Script for initial setup and dependencies
  config.vm.provision :shell, path: "install.sh"

  # Forward port mapping for Django development, HTTPS, and HTTP
  config.vm.network "forwarded_port", guest: 8000, host: 8000

  config.vm.synced_folder "./", "/vagrant", {:mount_options => ['dmode=777','fmode=777']}

  config.vm.provider "virtualbox" do |v|
    v.memory = 2048
    v.cpus = 2
  end
end

