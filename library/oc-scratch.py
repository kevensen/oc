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

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
module: oc
author:
- "Kenneth D. Evensen (@kevensen)"
short_description: Manage OpenShift Resources
description:
- This module allows management of resources in an OpenShift cluster.  This module gets executed on an OpenShift master and uses the system:admin's .kubeconfig file typically located at /root/.kube/config.  By default, this module uses the first (often the only) cluster entry under the "clusters" entry.  Thus, no API endpoint is required.

This is a self contained module and has no external dependencies.
version_added: "2.3"
options:
  kind:
    required: true
    description:
      - The kind of the resource upon which to take action.
"""

EXAMPLES = """

"""

RETURN = '''

...
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import BOOLEANS_TRUE
from ansible.module_utils.pycompat24 import get_exception
from itertools import chain
from collections import defaultdict
import base64
import json
import os
import requests
import yaml

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
                    self.cluster = self.parse_cluster_data(config['clusters'], host)

                self.api_version = self.cluster['cluster']['api-version']
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
                self.ansible.fail_json(msg='Unable to parse config file %s' % path)

    def parse_cluster_data(self, clusters, host):
        for cluster in clusters:
            if host == cluster['cluster']['server']:
                return cluster
        self.ansible.fail_json(msg='Unable to find cluster %s in kube config file' % host)

    def parse_user_data(self, users):
        for user in users:
            name = user['name'].split('/')[1]
            if name == self.name:
                self.client_cert = user['user']['client-certificate-data']
                self.client_key = user['user']['client-key-data']
                return
        self.ansible.fail_json(msg='Can not parse client certificate data out of config file %s.' % self.path)

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
            response = requests.get(url, cert=(self.kube_config.client_cert_file,
                                               self.kube_config.client_key_file),
                                         verify=self.kube_config.ca_file).json()
            for resource in response['resources']:
                self.kinds[resource['kind']] = {'kind': resource['kind'],
                                                'name': resource['name'].split('/')[0],
                                                'namespaced': resource['namespaced'],
                                                'api': api,
                                                'version': 'v1',
                                                'baseurl': url
                                                }

    def build_url(self, kind, name = None, namespace = None):
        url = self.kinds[kind]['baseurl']
        if self.kinds[kind]['namespaced'] == True:
            url += '/namespaces/'
            if namespace is None:
                self.module.fail_json(msg='Kind %s requires a namespace.  None provided' % kind)
            url += namespace

        url += '/'
        url += self.kinds[kind]['name']

        if name is not None:
            url += '/'
            url += name

        return url

    def get_resource(self, kind, namespace = None, name = None, uniqueify = False):
        url = ''
        if name is not None:
            url = self.build_url(kind, namespace=namespace, name=name)
        elif namespace is not None:
            url = self.build_url(kind, namespace=namespace)
        else:
            url = self.build_url(kind)

        resource = None
        response = requests.get(url, cert=(self.kube_config.client_cert_file,
                                           self.kube_config.client_key_file),
                                     verify=self.kube_config.ca_file)
        if response.status_code == 404:
            return {}
        if uniqueify:
            return self.uniqueify(response.json())

        return response.json()

    def create_resource(self, kind, namespace, name, inline):
        url = self.build_url(kind=kind, namespace=namespace)
        resource = None;
        change = False

        response = requests.post(url, cert=(self.kube_config.client_cert_file,
                                            self.kube_config.client_key_file),
                                     verify=self.kube_config.ca_file,
                                     data=json.dumps(inline))
        if response.status_code == 409:
            change = False
        elif response.status_code >= 300:
            self.module.fail_json(msg='Something went wrong creating the resource Kind: %s, Namespace: %s, Name: %s, error code: %s and resource definition: %s' %(kind, namespace, name, response.status_code, json.dumps(inline)))
        else:
            change = True

        return response.json(), change

    def replace_resource(self, kind, namespace, name, inline, existing_definition):
        #value = { k : existing_definition[k] for k in set(inline) - set(existing_definition) }
        #replacement = {}
        #replacement.update(existing_definition)
        #replacement.update(inline)

        replacement = dict(existing_definition, **inline)


        return replacement, False


    def process_absent(self, kind, namespace, name, check_mode):
        url = self.build_url(kind, namespace=namespace, name=name)
        response = None
        changed = False

        response = requests.get(url, cert=(self.kube_config.client_cert_file,
                                           self.kube_config.client_key_file),
                                     verify=self.kube_config.ca_file)

        if not check_mode:
            response = requests.delete(url, cert=(self.kube_config.client_cert_file,
                                               self.kube_config.client_key_file),
                                         verify=self.kube_config.ca_file)
        else:
            response = requests.get(url, cert=(self.kube_config.client_cert_file,
                                               self.kube_config.client_key_file),
                                         verify=self.kube_config.ca_file)
        if response.status_code == 200:
            changed = True
        elif response.status_code == 404:
            changed = False
        else:
            self.module.fail_json(msg='Something went wrong trying to delete resource named %s in namespace %s: %s' % (name, namespace, str(response.status_code)))
        return response.json(), changed

    def process_present(self, kind, namespace, name, uniqueify, inline, check_mode):
        resource = None
        change = False

        resource = self.get_resource(kind=kind,
                                     namespace=namespace,
                                     name=name,
                                     uniqueify=uniqueify)

        if resource != {}:
            if resource['kind'] == 'Status' and resource['metadata'] == {}:
                resource = {}

        if not check_mode:
            if resource == {} and inline is not None:
                resource, change = self.create_resource(kind, namespace, name, inline)
            elif resource != {} and inline is not None:
                resource, change = self.replace_resource(kind, namespace, name, inline, resource)

        return resource, change

    def uniqueify(self, resource):
        del resource['metadata']['creationTimestamp']
        del resource['metadata']['resourceVersion']
        del resource['metadata']['uid']
        return resource

def main():

    module = AnsibleModule(
        argument_spec=dict(
            force=dict(default=False, type='bool'),
            host=dict(required=False, type='str'),
            inline=dict(required=False, type='dict'),
            kind=dict(required=False, type='str'),
            name=dict(required=False, type='str'),
            namespace=dict(required=False, type='str'),

            path=dict(required=False, default='/root/.kube/config', type='str'),
            state=dict(required=True,
                       choices=['present', 'absent']),
            uniqueify=dict(default=True, type='bool')
        ),
        mutually_exclusive=(['name', 'inline'],
                            ['namespace', 'inline'],
        ),
        required_if=([['state', 'absent', ['kind']]]
        ),
        required_one_of=([['kind', 'inline']]),
        no_log=False,
        supports_check_mode=True
    )
    kind = None
    inline = None
    name = None
    namespace = None

    check_mode = module.check_mode
    force = module.params['force']
    host = module.params['host']
    inline = module.params['inline']
    path = module.params['path']
    state = module.params['state']
    uniqueify = module.params['uniqueify']

    if inline is not None:
        kind = module.params['inline']['kind']
        try:
            name = module.params['inline']['metadata']['name']
        except KeyError:
            pass
        try:
            namespace = module.params['inline']['metadata']['namespace']
        except KeyError:
            pass
    else:
        kind = module.params['kind'].capitalize()
        name = module.params['name']
        namespace = module.params['namespace']

    facts = {}
    resource = None
    kube_config = KubeConfig(path, host, module)
    oc = OC(kube_config, module)
    oc.build_facts()
    change = False

    if state == 'present' and inline is None:
        resource, change = oc.process_present(kind=kind,
                                      namespace=namespace,
                                      name=name,
                                      uniqueify=uniqueify,
                                      check_mode=check_mode)
    elif state == 'present' and inline is not None:
        resource, change = oc.process_present(kind=kind,
                                      namespace=namespace,
                                      name=name,
                                      uniqueify=uniqueify,
                                      inline=inline,
                                      check_mode=check_mode
                                      )


    elif state == 'absent':
        resource, change = oc.process_absent(kind=kind,
                                             namespace=namespace,
                                             name=name,
                                             check_mode=check_mode)

    facts['oc'] = {'resources': resource,
                   'url': oc.build_url(kind=kind,
                                       namespace=namespace,
                                       name=name),
                   'uniquified': uniqueify}
    kube_config.clean()
    module.exit_json(changed=change, ansible_facts=facts)

if __name__ == '__main__':
    main()
