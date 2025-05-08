package authz

default allow = false

# Entry point to check if a user has the 'admin' role on a resource
allow if {
    user_has_role(input.user, input.resource_id, "admin")
}

# Check if a user has a specific role on a resource
user_has_role(user, resource, role) if {
    data.assignments[user][resource] == role
}

# Return the role for a user on a specific resource
get_roles_for_user[role] if {
    user := input.user
    resource := input.resource_id
    role := data.assignments[user][resource]
}
