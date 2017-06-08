# from plugins/filter/json_query.py

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.listify import listify_lookup_plugin_terms



def remove_image(data, delete=False):
    for container in data['spec']['containers']:
        if not delete:
            container['image'] = ' '
        else:
            del container['image']
    return data

def translate_image_trigger(data, namespace):
    for trigger in data:
        if trigger['type'] in 'ImageChange':
            try:
                del trigger['imageChangeParams']['lastTriggeredImage']
            except KeyError:
                pass
            try:
                if trigger['imageChangeParams']['from']['namespace'] in namespace:
                    trigger['imageChangeParams']['from']['namespace'] = namespace
            except KeyError:
                pass

    return data

def uniqueify_resource(resource):
    try:
        del resource['metadata']['creationTimestamp']
        del resource['metadata']['resourceVersion']
        del resource['metadata']['uid']
    except KeyError:
        pass

    try:
        del resource['spec']['clusterIP']
    except KeyError:
        pass

    try:
        del resource['status']['ingress']
    except KeyError:
        pass

    return resource

class FilterModule(object):
    def filters(self):
        return {
            'remove_image': remove_image,
            'translate_image_trigger': translate_image_trigger,
            'uniqueify_resource': uniqueify_resource
        }
