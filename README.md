OC
=========

This role provides one library for the purposes of creating, modifying and/or deleting objects in the OpenShift Container Platform.  The oc.py library relies on an OpenShift service account and token for access and authorization.

Requirements
------------

Ansible 2.3

Role Variables
--------------

No specific role variables.

Dependencies
------------

This role depends on a service account to be created in each OpenShift cluster.  This can be accomplished similar to the following.
```terminal
$ oc project default
$ oc create serviceaccount ansible-sa
$ oadm policy add-cluster-role-to-user cluster-admin system:serviceaccount:default:ansible-sa
```
Please keep in mind that the above commands will create an extremely permissive service account.  It is recommended you tailor access controls as you deem necessary.

When the service account is created, OpenShift automatically creates a token in the form of a secret.  Use this token and create a variable to use in your playbooks.

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
      token: abcdefg
      validate_certs: false
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
