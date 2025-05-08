package authz

default allow := false

allow if {
	user_has_role(input.user, input.resource_id, "admin")
}

user_has_role(user, resource, role) if {
	data.assignments[user][resource] == role
}

get_roles_for_user[role] if {
	user := input.user
	resource := input.resource_id
	role := data.assignments[user][resource]
}
