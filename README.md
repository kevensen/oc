OC
=========

This role provides one library for the purposes of creating, modifying and/or deleting objects in the OpenShift Container Platform.  The oc.py library assumes that the target host has it's Kube config at /root/.kube/config.  This, of course, can be set with each task invocation.

Requirements
------------

Ansible 2.3

Role Variables
--------------

No specific role variables.

Dependencies
------------

No external dependencies.

Example Playbook
----------------

This is how a project might be deleted.
```
---
# file: oc.yml
- hosts: oc
  roles:
  - role: kevensen.oc
  tasks:
  - name: Delete "{{ project_name }}" Project
    oc:
      state: absent
      name: "{{ project_name }}"
      kind: project
    register: result
  - debug:
      var: result
  any_errors_fatal: true
  vars:
    ansible_become: true
    project_name: ansibletest
```

License
-------

GPLv3.

Author Information
------------------

Ken Evensen is a Solutions Architect with Red Hat.
