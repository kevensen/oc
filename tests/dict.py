#!/usr/bin/python




def print_dict(dictionary, ident = '', braces=1):
    """ Recursively prints nested dictionaries."""

    for key, value in dictionary.iteritems():
        if isinstance(value, dict):
            print '%s%s%s%s' %(ident,braces*'[',key,braces*']')
            print_dict(value, ident+'  ', braces+1)
        else:
            print ident+'%s = %s' %(key, value)

rb1 = { "apiVersion": "v1",
        "groupNames": None,
        "kind": "RoleBinding",
        "metadata": { "name": "admin",
                      "namespace": "ansibletest"
                    },
        "roleRef": { "name": "admin" },
        "subjects": [{
                       "kind": "SystemUser",
                       "name": "system:admin"
                     }],
        "userNames": [ "system:admin" ]
        }
rb2 = { "kind": "RoleBinding",
        "metadata": { "name": "admin",
                      "namespace": "ansibletest" },
        "roleRef": { "name": "admin" },
        "userNames": [ "kevensen" ]
     }

replacement = {}
replacement.update(rb1)
replacement.update(rb2)
print replacement
