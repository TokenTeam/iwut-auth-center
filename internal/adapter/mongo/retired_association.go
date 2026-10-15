package mongo

// Historical names are retained only for negative retirement checks. No schema,
// writer, migration or ordinary startup cleanup targets these development data.
const AssociationCollection = "auth_student_associations"
const AssociationMemberCollection = "auth_student_association_members"
