#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2017, Kenneth D. Evensen <kevensen@redhat.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pycompat24 import get_exception
import base64
import json
import os
import re
import requests
import yaml

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
module: oc
author:
- "Kenneth D. Evensen (@kevensen)"
short_description: Manage OpenShift Resources
description:
- This module allows management of resources in an OpenShift cluster.
This module gets executed on an OpenShift master and uses the system:admin's
.kubeconfig file typically located at /root/.kube/config.  By default, this
module uses the first (often the only) cluster entry under the "clusters"
entry. Thus, no API endpoint is required.

This is a self contained module and has no external dependencies.
version_added: "2.3"
options:
  kind:
    required: true
    description:
      - The kind of the resource upon which to take action.
  name:
    required: false
    description:
      - The name of the resource on which to take action.
  namespace:
    required: false
    description:
      - The namespace of the resource upon which to take action.
  inline:
    required: false
    description:
    - The inline definition of the resource.  This is mutually exclusive with
    name, namespace and kind.
  host:
    required: false
    description:
    - In the case that the ansible target is not the API endpoint, this value
    can be specified to match a host in the Kube config.
  path:
    required: false
    default: /root/.kube/config
    description:
    - The path to the kubeconfig file on the host.
  state:
    required: true
    choices:
    - present
    - absent
    description:
    - If the state is present, and the resource doesn't exist, it shall
    be created.  If the state is present and the resource exists, the
    definition will be updated, again using an inline definition.  If the
    state is absent, the resource will be deleted if it exists.

"""

EXAMPLES = """

- name: Create project
  oc:
    state: present
    inline:
      kind: ProjectRequest
      metadata:
        name: ansibletestproject
      displayName: Ansible Test Project
      description: This project was created using Ansible

- name: Delete a service
  oc:
    state: absent
    name: myservice
    namespace: mynamespace
    kind: Service

- name: Add project role Admin to a user
  oc:
    state: present
    inline:
      kind: RoleBinding
      metadata:
        name: admin
        namespace: mynamespace
      roleRef:
        name: admin
      userNames:
      - "myuser"

"""

RETURN = '''
result:
  description: The resource that was created or changed.  In the case of
  a deletion, this is the response from the delete request.
  returned: success
  type: string
uniquified:
  description: Whether or not the returned object has been uniquified.
  returned: success
  type: boolean
url:
  description: The URL to the requested resource.
  returned: success
  type: string
...
'''



class KubeConfig(object):
    def __init__(self, path, host, ansible):
        yml = []
        self.path = path
        self.host = host
        self.ansible = ansible
        with open(path, 'r') as stream:
            try:
                config = yaml.load(stream)
                if not host:
                    self.cluster = config['clusters'][0]
                    self.host = self.cluster['cluster']['server']
                else:
                    self.cluster = self.parse_cluster_data(
                                                    config['clusters'],
                                                    host)
                if 'api-version' in self.cluster['cluster'].keys():
                    self.api_version = self.cluster['cluster']['api-version']
                else:
                    self.api_version = config['apiVersion']
                self.ca = self.cluster['cluster']['certificate-authority-data']
                self.server = self.cluster['cluster']['server']
                self.name = self.cluster['name']

                self.parse_user_data(config['users'])

                self.client_cert_file = '/tmp/' + self.name + '-cert.pem'
                self.client_key_file = '/tmp/' + self.name + '-key.pem'
                self.ca_file = '/tmp/' + self.name + '-ca-cert.pem'
                self.write_file(self.client_cert_file, self.client_cert)
                self.write_file(self.client_key_file, self.client_key)
                self.write_file(self.ca_file, self.ca)
            except yaml.YAMLError as exc:
                self.ansible.fail_json(msg='Unable to parse config file %s'
                                       % path)

    def parse_cluster_data(self, clusters, host):
        for cluster in clusters:
            if host == cluster['cluster']['server']:
                return cluster
        self.ansible.fail_json(
                        msg='Unable to find cluster %s in kube config file'
                        % host)

    def parse_user_data(self, users):
        for user in users:
            name = user['name'].split('/')[1]
            if name == self.name:
                self.client_cert = user['user']['client-certificate-data']
                self.client_key = user['user']['client-key-data']
                return
        self.ansible.fail_json(
            msg='Can not parse client certificate data out of config file %s.'
            % self.path)

    def write_file(self, file_name, cert_string):
        self.ansible.log("Writing temporary file %s" % file_name)
        f = open(file_name, 'w')
        f.write(base64.standard_b64decode(cert_string))
        f.close()

    def clean(self):
        os.remove(self.client_key_file)
        os.remove(self.client_cert_file)
        os.remove(self.ca_file)


class OC(object):
    def __init__(self, kube_config, module):
        self.apis = ['api', 'oapi']
        self.kube_config = kube_config
        self.module = module
        self.kinds = {}

    def build_facts(self):
        for api in self.apis:
            url = self.kube_config.host + "/" + api + "/v1"
            response = requests.get(url,
                                    cert=(self.kube_config.client_cert_file,
                                          self.kube_config.client_key_file),
                                    verify=self.kube_config.ca_file).json()
            for resource in response['resources']:
                if not 'generated' in resource['name']:
                    self.kinds[resource['kind']] = {'kind': resource['kind'],
                                                    'name': resource['name'].split('/')[0],
                                                    'namespaced': resource['namespaced'],
                                                    'api': api,
                                                    'version': 'v1',
                                                    'baseurl': url
                                                    }


class Resource(object):
    def __init__(self, kube_config, module, kinds,
                 kind, namespace=None, name=None):
        self.kube_config = kube_config
        self.module = module
        self.kinds = kinds
        self.kind = kind
        self.namespace = namespace
        self.name = name

    def url(self):
        url = self.kinds[self.kind]['baseurl']
        if self.kinds[self.kind]['namespaced'] is True:
            url += '/namespaces/'
            if self.namespace is None:
                self.module.fail_json(msg='Kind %s requires a namespace.  \
                                      None provided' % self.kind)
            url += self.namespace

        url += '/'
        url += self.kinds[self.kind]['name']

        if self.name is not None:
            url += '/'
            url += self.name
        self.module.log(msg="URL for request is %s" % url)
        return url

    def merge(self, source, destination, changed):

        for key, value in source.items():
            if isinstance(value, dict):
                # get node or create one
                try:
                    node = destination.setdefault(key, {})
                except AttributeError:
                    node = {}
                finally:
                    _, changed = self.merge(value, node, changed)

            elif isinstance(value, list) and key in destination.keys():
                try:
                    if set(destination[key]) != set(destination[key] +
                                                    source[key]):
                        destination[key] = list(set(destination[key] +
                                                    source[key]))
                        changed = True
                except TypeError:
                    for new_dict in source[key]:
                        found = False
                        for old_dict in destination[key]:
                            if 'name' in old_dict.keys() and 'name' in new_dict.keys():
                                if old_dict['name'] == new_dict['name']:
                                    destination[key].remove(old_dict)
                                    break
                            if cmp(old_dict, new_dict) == 0:
                                found = True
                                break

                        if not found:
                            destination[key].append(new_dict)
                            changed = True

            elif (key not in destination.keys() or
                  destination[key] != source[key]):
                destination[key] = value
                changed = True
        return destination, changed

    def get(self, fieldSelector=''):
        resource = None
        response = None
        if fieldSelector is not '':
            response = requests.get(self.url(),
                                    params={'fieldSelector': fieldSelector},
                                    cert=(self.kube_config.client_cert_file,
                                          self.kube_config.client_key_file),
                                    verify=self.kube_config.ca_file)
        else:
            response = requests.get(self.url(),
                                    cert=(self.kube_config.client_cert_file,
                                          self.kube_config.client_key_file),
                                    verify=self.kube_config.ca_file)

        if response.json() is not None and response.json() != {}:
            if (response.json()['kind'] == 'Status' and
                    response.json()['metadata'] == {}):
                return None

        if response.status_code == 404:
            return None

        resource = response.json()

        return resource

    def exists(self):
        if self.get() is not None:
            return True
        return False

    def create(self, inline):
        changed = False

        inline['kind'] = self.kind
        inline['apiVersion'] = self.kinds[self.kind]['version']

        self.module.log(
            msg="JSON body for create request is %s"
            % json.dumps(inline))

        url = self.url()[:self.url().rfind('/')]
        response = requests.post(url,
                                 data=json.dumps(inline),
                                 cert=(self.kube_config.client_cert_file,
                                       self.kube_config.client_key_file),
                                 verify=self.kube_config.ca_file)

        self.module.log(
            msg="Response for create request is %s"
            % str(response.json()))

        if response.status_code == 404:
            return None, changed
        elif response.status_code == 409:
            return response.json(), changed
        elif response.status_code >= 300:
            self.module.fail_json(
                msg='Failed to create resource %s in \
                namespace %s with msg %s' % (self.name,
                self.namespace, response.reason))
        else:
            changed = True
            return response.json(), changed

    def replace(self, inline):
        changed = False
        resource = self.get()
        self.module.log(
            msg="Found existing resource for update request: %s"
            % str(resource))
        new_resource, changed = self.merge(inline, resource, changed)

        if changed:
            self.module.log(
                msg="JSON body for update request is %s"
                % json.dumps(new_resource))
            response = requests.put(self.url(),
                                    data=json.dumps(new_resource),
                                    cert=(self.kube_config.client_cert_file,
                                          self.kube_config.client_key_file),
                                    verify=self.kube_config.ca_file)
            self.module.log(
                msg="Response for update request is %s"
                % str(response.json()))

            if response.status_code >= 300:
                self.module.fail_json(
                    msg='Failed to update resource %s in \
                    namespace %s with msg %s'
                    % (self.name, self.namespace, response.reason))

            return response.json(), changed
        return resource, changed

    def delete(self):

        changed = False

        response = requests.delete(self.url(),
                                   cert=(self.kube_config.client_cert_file,
                                         self.kube_config.client_key_file),
                                   verify=self.kube_config.ca_file)

        self.module.log(
            msg="Response for delete request is %s"
            % str(response.json()))

        if response.status_code == 404:
            return None, changed
        elif response.status_code >= 300:
            self.module.fail_json(msg='Failed to delete resource %s in \
                                  namespace %s with msg %s'
                                  % (name, namespace, response.msg))
        else:
            changed = True
            return response.json(), changed

def main():

    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=False, type='str'),
            inline=dict(required=False, type='dict'),
            kind=dict(required=False, type='str'),
            name=dict(required=False, type='str'),
            namespace=dict(required=False, type='str'),

            path=dict(required=False,
                      default='/root/.kube/config',
                      type='str'),
            fieldSelector=dict(required=False, default='', type='str'),
            state=dict(required=True,
                       choices=['present', 'absent'])
        ),
        mutually_exclusive=(['kind', 'inline']),
        required_if=([['state', 'absent', ['kind']]]),
        required_one_of=([['kind', 'inline']]),
        no_log=False,
        supports_check_mode=False
    )
    kind = None
    inline = None
    name = None
    namespace = None

    host = module.params['host']
    inline = module.params['inline']
    path = module.params['path']
    state = module.params['state']
    kind = module.params['kind']
    fieldSelector = module.params['fieldSelector']
    name = module.params['name']
    namespace = module.params['namespace']

    if inline is not None:
        kind = inline['kind']
        try:
            if name is None:
                name = inline['metadata']['name']
            else:
                inline['metadata']['name'] = name
        except KeyError:
            pass

        try:
            if namespace is None:
                namespace = inline['metadata']['namespace']
            else:
                inline['metadata']['namespace'] = namespace
        except KeyError:
            pass


    result = None
    kube_config = KubeConfig(path, host, module)
    oc = OC(kube_config, module)
    oc.build_facts()
    changed = False
    method = ''

    resource = Resource(kube_config=kube_config,
                        module=module,
                        kinds=oc.kinds,
                        kind=kind,
                        namespace=namespace,
                        name=name)

    if state == 'present' and resource.exists() and inline is None:
        result = resource.get(fieldSelector=fieldSelector)
        method = 'get'
    elif state == 'present' and resource.exists():
        result, changed = resource.replace(inline=inline)
        method = 'put'
    elif state == 'present' and not resource.exists() and inline is not None:
        result, changed = resource.create(inline=inline)
        method = 'create'
    elif state == 'absent' and resource.exists():
        result, changed = resource.delete()
        method = 'delete'
    facts = {}

    if "items" in result.keys():
        result['item_list'] = result.pop('items')
    facts['oc'] = {'result': result,
                   'url': resource.url(),
                   'method': method}

    kube_config.clean()
    module.exit_json(changed=changed, ansible_facts=facts)

if __name__ == '__main__':
    main()
