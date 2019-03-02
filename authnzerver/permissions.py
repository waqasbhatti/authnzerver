#!/usr/bin/env python
# -*- coding: utf-8 -*-
# permissions.py - Waqas Bhatti (wbhatti@astro.princeton.edu) - Aug 2018
# License: MIT - see the LICENSE file for the full text.

'''
This contains the permissions and user-role models for authnzerver.

'''


######################################
## ROLES AND ASSOCIATED PERMISSIONS ##
######################################

# these are the basic permissions for roles
ROLE_PERMISSIONS = {
    'superuser':{
        'limits':{
            'max_req_items': 5000000,
            'max_reqs_60sec': 60000,
        },
        'can_own':{'dataset','object','collection','apikeys','preferences'},
        'for_owned': {
            'list',
            'view',
            'create',
            'delete',
            'edit',
            'make_public',
            'make_unlisted',
            'make_private',
            'make_shared',
            'change_owner',
        },
        'for_others':{
            'public':{
                'list',
                'view',
                'create',
                'delete',
                'edit',
                'make_private',
                'make_unlisted',
                'make_shared',
                'change_owner',
            },
            'unlisted':{
                'list',
                'view',
                'create',
                'delete',
                'edit',
                'make_public',
                'make_private',
                'make_shared',
                'change_owner',
            },
            'shared':{
                'list',
                'view',
                'create',
                'delete',
                'edit',
                'make_public',
                'make_unlisted',
                'make_private',
                'change_owner',
            },
            'private':{
                'list',
                'view',
                'create',
                'delete',
                'edit',
                'make_public',
                'make_unlisted',
                'make_shared',
                'change_owner',
            },
        }
    },
    'staff':{
        'limits':{
            'max_req_items': 1000000,
            'max_reqs_60sec': 60000,
        },
        'can_own':{'dataset','object','collection','apikeys','preferences'},
        'for_owned': {
            'list',
            'view',
            'create',
            'delete',
            'edit',
            'make_public',
            'make_unlisted',
            'make_private',
            'make_shared',
            'change_owner',
        },
        'for_others':{
            'public':{
                'list',
                'view',
                'edit',
                'delete',
            },
            'unlisted':{
                'list',
                'view',
                'edit',
                'delete',
            },
            'shared':{
                'list',
                'view',
                'edit',
            },
            'private':{
                'list',
            },
        }
    },
    'authenticated':{
        'limits':{
            'max_req_items': 500000,
            'max_reqs_60sec': 6000,
        },
        'can_own':{'dataset','apikeys','preferences'},
        'for_owned': {
            'list',
            'view',
            'create',
            'delete',
            'edit',
            'make_public',
            'make_unlisted',
            'make_private',
            'make_shared',
        },
        'for_others':{
            'public':{
                'list',
                'view',
            },
            'unlisted':{
                'view',
            },
            'shared':{
                'list',
                'view',
                'edit',
            },
            'private':set({}),
        }
    },
    'anonymous':{
        'limits':{
            'max_req_items': 100000,
            'max_reqs_60sec': 600,
        },
        'can_own':{'dataset'},
        'for_owned': {
            'list',
            'view',
            'create',
            'make_private',
            'make_public',
            'make_unlisted',
        },
        'for_others':{
            'public':{
                'list',
                'view',
            },
            'unlisted':{
                'view'
            },
            'shared':set({}),
            'private':set({}),
        }
    },
    'locked':{
        'limits':{
            'max_req_items': 0,
            'max_reqs_60sec': 0,
        },
        'can_own':set({}),
        'for_owned': set({}),
        'for_others':{
            'public':set({}),
            'unlisted':set({}),
            'shared':set({}),
            'private':set({}),
        }
    },
}

# these are intersected with each role's permissions above to form the final set
# of permissions available for each item
ITEM_PERMISSIONS = {
    'object':{
        'valid_permissions':{'list',
                             'view',
                             'create',
                             'edit',
                             'delete',
                             'change_owner',
                             'make_public',
                             'make_unlisted',
                             'make_shared',
                             'make_private'},
        'valid_visibilities':{'public',
                              'unlisted',
                              'private',
                              'shared'},
        'invalid_roles':set({'locked'}),
    },
    'dataset':{
        'valid_permissions':{'list',
                             'view',
                             'create',
                             'edit',
                             'delete',
                             'change_owner',
                             'make_public',
                             'make_unlisted',
                             'make_shared',
                             'make_private'},
        'valid_visibilities':{'public',
                              'unlisted',
                              'private',
                              'shared'},
        'invalid_roles':set({'locked'}),
    },
    'collection':{
        'valid_permissions':{'list',
                             'view',
                             'create',
                             'edit',
                             'delete',
                             'change_owner',
                             'make_public',
                             'make_unlisted',
                             'make_shared',
                             'make_private'},
        'valid_visibilities':{'public',
                              'unlisted',
                              'private',
                              'shared'},
        'invalid_roles':set({'locked'}),
    },
    'users':{
        'valid_permissions':{'list',
                             'view',
                             'edit',
                             'create',
                             'delete'},
        'valid_visibilities':{'private'},
        'invalid_roles':set({'authenticated','anonymous','locked'}),

    },
    'sessions':{
        'valid_permissions':{'list',
                             'view',
                             'delete'},
        'valid_visibilities':{'private'},
        'invalid_roles':set({'authenticated','anonymous','locked'}),

    },
    'apikeys':{
        'valid_permissions':{'list',
                             'view',
                             'create',
                             'delete'},
        'valid_visibilities':{'private'},
        'invalid_roles':set({'anonymous','locked'}),

    },
    'preferences':{
        'valid_permissions':{'list',
                             'view',
                             'edit'},
        'valid_visibilities':{'private'},
        'invalid_roles':set({'anonymous','locked'}),
    }
}


###########################################
## GENERATING PERMISSION AND ROLE MODELS ##
###########################################




##########################
## CHECKING PERMISSIONS ##
##########################

def get_item_permissions(role_name,
                         target_name,
                         target_visibility,
                         target_scope,
                         debug=False,
                         all_role_permissions=None,
                         all_item_permissions=None):
    '''Returns the possible permissions for a target given a role and target
    status.

    role is one of {superuser, authenticated, anonymous, locked}

    target_name is one of {object, dataset, collection, users,
                           apikeys, preferences, sessions}

    target_visibility is one of {public, private, shared}

    target_scope is one of {owned, others}

    Returns a set. If the permissions don't make sense, returns an empty set, in
    which case access MUST be denied.

    '''

    if not all_role_permissions:
        all_role_permissions = ROLE_PERMISSIONS
    if not all_item_permissions:
        all_item_permissions = ITEM_PERMISSIONS

    if debug:
        print(
            'role_name = %s\ntarget_name = %s\n'
            'target_visibility = %s\ntarget_scope = %s' %
            (role_name, target_name, target_visibility, target_scope)
        )

    try:
        target_valid_permissions = all_item_permissions[
            target_name
        ]['valid_permissions']
        target_valid_visibilities = all_item_permissions[
            target_name
        ]['valid_visibilities']
        target_invalid_roles = all_item_permissions[
            target_name
        ]['invalid_roles']

        if debug:
            print('%s valid_perms: %r' %
                  (target_name, target_valid_permissions))
            print('%s valid_visibilities: %r' %
                  (target_name, target_valid_visibilities))
            print('%s invalid_roles: %r' %
                  (target_name, target_invalid_roles))


        # if the role is not allowed into this target, return
        if role_name in target_invalid_roles:
            return set({})

        # if the target's status is not valid, return
        if target_visibility not in target_valid_visibilities:
            return set({})

        # check the target's scope

        # if this target is owned by the user, then check target owned
        # permissions
        if target_scope == 'for_owned':
            role_permissions = all_role_permissions[role_name][target_scope]

        # otherwise, the target is not owned by the user, check scope
        # permissions for target status
        else:
            role_permissions = (
                all_role_permissions[role_name][target_scope][target_visibility]
            )

        # these are the final available permissions
        available_permissions = role_permissions.intersection(
            target_valid_permissions
        )

        if debug:
            print("target role permissions: %r" % role_permissions)
            print('available actions for role: %r' % available_permissions)

        return available_permissions

    except Exception as e:
        return set({})


def check_user_access(userid=2,
                      role='anonymous',
                      action='view',
                      target_name='collection',
                      target_owner=1,
                      target_visibility='private',
                      target_sharedwith=None,
                      debug=False,
                      all_role_permissions=None,
                      all_item_permissions=None):
    '''
    This does a check for user access to a target.

    '''

    if not all_role_permissions:
        all_role_permissions = ROLE_PERMISSIONS
    if not all_item_permissions:
        all_item_permissions = ITEM_PERMISSIONS

    if debug:
        print('userid = %s\ntarget_owner = %s\nsharedwith_userids = %s' %
              (userid, target_owner, target_sharedwith))

    if role in ('superuser', 'staff'):

        shared_or_owned_ok = True

    elif target_visibility == 'private':

        shared_or_owned_ok = userid == target_owner

    elif target_visibility == 'shared':

        try:

            if target_sharedwith and target_sharedwith != '':

                sharedwith_userids = target_sharedwith.split(',')
                sharedwith_userids = [int(x) for x in sharedwith_userids]
                if debug:
                    print('sharedwith_userids = %s' % sharedwith_userids)
                shared_or_owned_ok = (
                    userid in sharedwith_userids or userid == target_owner
                )

                # anything shared with anonymous users is effectively shared for
                # everyone
                if 2 in sharedwith_userids:
                    shared_or_owned_ok = True

            else:
                shared_or_owned_ok = (
                    userid == target_owner
                )

        except Exception as e:
            shared_or_owned_ok = False

    # unlisted objects are OK to view
    elif target_visibility == 'unlisted':

        shared_or_owned_ok = True

    elif target_visibility == 'public':

        shared_or_owned_ok = True

    else:

        shared_or_owned_ok = False


    if debug:
        print('target shared or owned test passed = %s' % shared_or_owned_ok)

    target_may_be_owned_by_role = (
        target_name in all_role_permissions[role]['can_own']
    )

    if debug:
        print("target: '%s' may be owned by role: '%s' = %s" %
              (target_name, role, target_may_be_owned_by_role))

    # validate ownership of the target
    if (userid == target_owner and target_may_be_owned_by_role):
        perms = get_item_permissions(role,
                                     target_name,
                                     target_visibility,
                                     'for_owned',
                                     debug=debug)

    # if the target is not owned, then check if it's accessible under its scope
    # and visibility
    elif userid != target_owner:
        perms = get_item_permissions(role,
                                     target_name,
                                     target_visibility,
                                     'for_others',
                                     debug=debug)

    # if the target cannot be owned by the role, then fail
    else:
        perms = set({})

    if debug:
        print("user action: '%s', permitted actions: %s" % (action, perms))

    return ((action in perms) and shared_or_owned_ok)



def check_role_limits(role,
                      requested_items=None,
                      rate_60sec=None,
                      all_role_permissions=None):
    '''
    This just returns the role limits.

    '''

    if not all_role_permissions:
        all_role_permissions = ROLE_PERMISSIONS

    if requested_items is not None:
        return (
            all_role_permissions[role]['limits']['max_req_items'] <= (
                requested_items
            )
        )
    elif rate_60sec is not None:
        return (
            all_role_permissions[role]['limits']['max_reqs_60sec'] >= (
                rate_60sec
            )
        )
    else:
        return all_role_permissions[role]['limits']
