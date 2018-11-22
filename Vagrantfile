# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|

  config.vm.define 'bouncer' do |vm_cfg|

    vm_cfg.vm.box = "ubuntu/trusty64"
    vm_cfg.vm.hostname = 'bouncer'
    vm_cfg.vm.provision "docker"

    config.vm.synced_folder '.', '/vagrant', type: :virtualbox

    vm_cfg.vm.provider :virtualbox do |v|
      v.name = vm_cfg.vm.hostname
      v.cpus = 2
      v.memory = 8192
    end
  end
end
